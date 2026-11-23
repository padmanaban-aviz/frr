#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_lag_topo5.py
#
# Copyright (C) 2026 Aviz Networks
#
# BFD over the bond (BLB) together with RFC 7130 micro-BFD, logical mode
# ("bundle coexistence bob-blb logical"):
#
#   r1 [bond0: r1-eth0, r1-eth1] ===== [bond0: r2-eth0, r2-eth1] r2
#
# Each end runs micro-BFD on both members (200 ms x 3, detection 600 ms)
# and one BLB session on bond0 (UDP 3784).
#
# - the BLB session comes Up next to the micro-BFD sessions;
# - BLB 400 ms x 3 (1200 ms) is below 600 + 500 + 400 = 1500 ms: show, JSON
#   and the log say it is too fast;
# - BLB 600 ms x 3 (1800 ms) meets 600 + 500 + 600 = 1700 ms: the warning
#   clears;
# - one link fails silently in both directions: micro-BFD holds the member
#   down, the bond rehashes, and the BLB session stays Up;
# - removing the command stops the check.
#
# Skipped when the kernel has no bonding support.
#

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bfdd]

MEMBERS = {"r1": ("r1-eth0", "r1-eth1"), "r2": ("r2-eth0", "r2-eth1")}
PEER = {"r1": "10.0.50.2", "r2": "10.0.50.1"}


def build_topo(tgen):
    "Two routers joined by two direct links."
    for rname in ("r1", "r2"):
        tgen.add_router(rname)
    # Direct links: a Linux bridge in between would not forward LACPDUs.
    for i in range(2):
        tgen.add_link(
            tgen.gears["r1"],
            tgen.gears["r2"],
            "r1-eth{}".format(i),
            "r2-eth{}".format(i),
        )


def _have_bonding(router):
    router.run("ip link add bondprobe type bond")
    try:
        ok = bool(
            json.loads(router.run("ip -j link show bondprobe 2>/dev/null") or "[]")
        )
    except ValueError:
        ok = False
    if ok:
        router.run("ip link del bondprobe")
    return ok


def setup_module(mod):
    "Set up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        if not _have_bonding(router):
            continue
        router.run("ip link add bond0 type bond mode 802.3ad lacp_rate fast miimon 100")
        for member in MEMBERS[rname]:
            router.run("ip link set {} down".format(member))
            router.run("ip link set {} master bond0".format(member))
        router.run("ip link set bond0 up")

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
    tgen.start_router()


def teardown_module():
    "Tear down the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _skip(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if not _have_bonding(tgen.gears["r1"]):
        pytest.skip("kernel has no bonding support")


def _dump(tgen):
    "Bond, micro-BFD and BLB state of both routers, for a failed check."
    lines = []
    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        lines.append("===== {} /proc/net/bonding/bond0".format(rname))
        lines.append(router.run("cat /proc/net/bonding/bond0"))
        lines.append("===== {} show bfd lag".format(rname))
        lines.append(router.vtysh_cmd("show bfd lag"))
        lines.append("===== {} show bfd peers".format(rname))
        lines.append(router.vtysh_cmd("show bfd peers"))
    path = os.path.join(tgen.logdir, "bond_state.txt")
    with open(path, "a") as f:
        f.write("\n".join(lines) + "\n")


def _expect(func, *args, count=60, wait=1):
    _, result = topotest.run_and_expect(
        functools.partial(func, *args), None, count, wait
    )
    if result is not None:
        _dump(get_topogen())
    assert result is None, result


def _lag(router, bond="bond0"):
    try:
        out = json.loads(router.vtysh_cmd("show bfd lag {} json".format(bond)))
    except ValueError:
        return {}
    return out.get(bond, {})


def _blb_peer(router):
    "The BLB session, from show bfd peers json."
    try:
        peers = json.loads(router.vtysh_cmd("show bfd peers json"))
    except ValueError:
        return {}
    for p in peers:
        if p.get("peer") == PEER[router.name] and p.get("interface") == "bond0":
            return p
    return {}


def _blb_downs(router):
    "session-down count of the BLB session."
    try:
        peers = json.loads(router.vtysh_cmd("show bfd peers counters json"))
    except ValueError:
        return None
    for p in peers:
        if p.get("peer") == PEER[router.name] and p.get("interface") == "bond0":
            return p.get("session-down")
    return None


def _micro_up(tgen):
    for rname, members in MEMBERS.items():
        lag = _lag(tgen.gears[rname])
        for ifname in members:
            m = lag.get("members", {}).get(ifname, {})
            state = m.get("microBfdIpv4", {}).get("localState")
            if state != "up" or m.get("detached") is not False:
                return "{}: {} session {}, detached {}".format(
                    rname, ifname, state, m.get("detached")
                )
    return None


def _blb_up(tgen):
    for rname in ("r1", "r2"):
        p = _blb_peer(tgen.gears[rname])
        if p.get("status") != "up":
            return "{}: BLB session {}".format(rname, p.get("status"))
    return None


def _blb_rule(tgen, ok, detect, need):
    "Every end reports the rule as `ok`, BLB detection `detect`, needing `need` ms."
    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        lag = _lag(router)
        if lag.get("blbMode") != "logical":
            return "{}: blbMode {}".format(rname, lag.get("blbMode"))
        if lag.get("blbMicroDetectionTime") != 600:
            return "{}: micro detection {}".format(
                rname, lag.get("blbMicroDetectionTime")
            )
        if lag.get("blbRehashAllowance") != 500:
            return "{}: rehash allowance {}".format(
                rname, lag.get("blbRehashAllowance")
            )
        s = lag.get("blbSessions", {}).get(PEER[rname], {})
        if (
            s.get("ok") != ok
            or s.get("detectionTime") != detect
            or s.get("requiredDetectionTime") != need
        ):
            return "{}: BLB session in show bfd lag {}".format(rname, s)
        b = _blb_peer(router).get("blb", {})
        if (
            b.get("lag") != "bond0"
            or b.get("ok") != ok
            or b.get("requiredDetectionTime") != need
        ):
            return "{}: blb in show bfd peers {}".format(rname, b)
    return None


def _set_blb_timers(tgen, ms):
    for router in tgen.routers().values():
        router.vtysh_cmd(
            "configure terminal\n"
            "bfd\n"
            "profile blb\n"
            "receive-interval {0}\n"
            "transmit-interval {0}\n".format(ms)
        )


def _drop_link(tgen, idx, drop):
    "Silent failure of link `idx`: drop every IP packet leaving both ends."
    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        ifname = MEMBERS[rname][idx]
        if drop:
            router.run("tc qdisc add dev {} clsact".format(ifname))
            router.run(
                "tc filter add dev {} egress protocol ip u32 "
                "match u32 0 0 action drop".format(ifname)
            )
        else:
            router.run("tc qdisc del dev {} clsact".format(ifname))


def test_sessions_up():
    "micro-BFD on both members and the BLB session come Up."
    tgen = get_topogen()
    _skip(tgen)

    _expect(_micro_up, tgen)
    _expect(_blb_up, tgen)

    out = tgen.gears["r1"].vtysh_cmd("show running-config bfdd")
    assert "bundle coexistence bob-blb logical" in out, out


def test_rule_broken():
    "BLB 400 ms x 3 is too fast for micro-BFD 200 ms x 3: warned."
    tgen = get_topogen()
    _skip(tgen)

    _expect(_blb_rule, tgen, False, 1200, 1500, count=30)
    out = tgen.gears["r1"].vtysh_cmd("show bfd lag bond0")
    assert "rehash allowance 500 ms" in out, out
    assert "needs 1500 ms, too fast" in out, out


def test_rule_met():
    "BLB 600 ms x 3 meets the rule: the warning clears."
    tgen = get_topogen()
    _skip(tgen)

    _set_blb_timers(tgen, 600)
    _expect(_blb_rule, tgen, True, 1800, 1700, count=30)
    _expect(_blb_up, tgen)


def test_member_failure():
    "A silent link failure: micro-BFD takes the member out, BLB stays Up."
    tgen = get_topogen()
    _skip(tgen)

    downs = {rname: _blb_downs(tgen.gears[rname]) for rname in ("r1", "r2")}

    def _detach_count(rname):
        m = _lag(tgen.gears[rname]).get("members", {}).get(MEMBERS[rname][0], {})
        return m.get("detachCount", 0)

    held_before = {rname: _detach_count(rname) for rname in ("r1", "r2")}

    _drop_link(tgen, 0, True)

    def _held():
        # Held down at least once (the recovery probe releases it on
        # probation every few seconds, so its state alone keeps changing).
        for rname in ("r1", "r2"):
            if _detach_count(rname) <= held_before[rname]:
                return "{}: {} not held down".format(rname, MEMBERS[rname][0])
        return None

    _expect(_held, count=30)
    _expect(_blb_up, tgen, count=5)
    for rname in ("r1", "r2"):
        now = _blb_downs(tgen.gears[rname])
        assert now == downs[rname], "{}: BLB went down ({} -> {})".format(
            rname, downs[rname], now
        )

    _drop_link(tgen, 0, False)
    _expect(_micro_up, tgen, count=90)


def test_mode_removed():
    "Without the command the BLB timers are no longer checked."
    tgen = get_topogen()
    _skip(tgen)

    # Too fast again, then remove the command.
    _set_blb_timers(tgen, 400)
    _expect(_blb_rule, tgen, False, 1200, 1500, count=30)
    for router in tgen.routers().values():
        router.vtysh_cmd("configure terminal\nbfd\nno bundle coexistence bob-blb\n")

    def _off():
        for rname in ("r1", "r2"):
            router = tgen.gears[rname]
            lag = _lag(router)
            if lag.get("blbMode") != "none" or "blbSessions" in lag:
                return "{}: {}".format(rname, lag.get("blbMode"))
            if "blb" in _blb_peer(router):
                return "{}: blb still in show bfd peers".format(rname)
        return None

    _expect(_off, count=10)
    _expect(_blb_up, tgen, count=10)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
