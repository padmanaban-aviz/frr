#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_lag_topo3.py
#
# Copyright (C) 2026 Aviz Networks
#
# RFC 7130 micro-BFD failure-mode and admin-down-hold, between two FRR
# routers over a two-member bond:
#
#   r1 [bond0: r1-eth0, r1-eth1] ===== [bond0: r2-eth0, r2-eth1] r2
#
# r1 runs failure-mode closed, r2 the default (open).
#
# - failure-mode reaches zebra, and a change at runtime too;
# - failure-mode closed: bfdd killed with a member out, the member stays
#   out; after bfdd is back, it goes back in only when its session is Up;
# - admin-down-hold: the peer's AdminDown keeps members in for that long,
#   then they go out ("peer AdminDown, hold expired"); a new value applies
#   to a hold already running; 0 keeps members in again;
# - failure-mode open on a balance-xor bond is warned about.
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
from lib.common_config import kill_router_daemons, start_router_daemons
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bfdd]

MEMBERS = {"r1": ("r1-eth0", "r1-eth1"), "r2": ("r2-eth0", "r2-eth1")}


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


def _dump_bonds(tgen):
    "Bond and micro-BFD state of both routers, for a failed check."
    lines = []
    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        lines.append("===== {} /proc/net/bonding/bond0".format(rname))
        lines.append(router.run("cat /proc/net/bonding/bond0"))
        lines.append("===== {} show bfd lag".format(rname))
        lines.append(router.vtysh_cmd("show bfd lag"))
    path = os.path.join(tgen.logdir, "bond_state.txt")
    with open(path, "a") as f:
        f.write("\n".join(lines) + "\n")


def _expect(func, *args, count=60, wait=1):
    _, result = topotest.run_and_expect(
        functools.partial(func, *args), None, count, wait
    )
    if result is not None:
        _dump_bonds(get_topogen())
    assert result is None, result


def _lag(router, bond="bond0"):
    try:
        out = json.loads(router.vtysh_cmd("show bfd lag {} json".format(bond)))
    except ValueError:
        return {}
    return out.get(bond, {})


def _master(router, ifname):
    try:
        link = json.loads(router.run("ip -j -d link show dev {}".format(ifname)))[0]
    except (ValueError, IndexError):
        return None
    return link.get("master", "")


def _member(router, ifname):
    return _lag(router).get("members", {}).get(ifname, {})


def _member_state(router, ifname, state=None, detached=None, distributing=None):
    m = _member(router, ifname)
    if not m:
        return "{}: {} not reported".format(router.name, ifname)
    got = m.get("microBfdIpv4", {}).get("localState")
    if state is not None and got != state:
        return "{}: {} session {}, expected {}".format(router.name, ifname, got, state)
    if detached is not None and m.get("detached") != detached:
        return "{}: {} detached={} (reason {!r})".format(
            router.name, ifname, m.get("detached"), m.get("reason")
        )
    if distributing is not None and m.get("distributing") != distributing:
        return "{}: {} distributing={}".format(
            router.name, ifname, m.get("distributing")
        )
    if detached is not None:
        kernel = _master(router, ifname)
        if detached and kernel != "":
            return "{}: {} still in {} in the kernel".format(
                router.name, ifname, kernel
            )
        if detached is False and kernel != "bond0":
            return "{}: {} not in bond0 in the kernel ({!r})".format(
                router.name, ifname, kernel
            )
    return None


def _all_up(tgen):
    for rname, members in MEMBERS.items():
        router = tgen.gears[rname]
        if _lag(router).get("status") != "ok":
            return "{}: lag status {}".format(rname, _lag(router).get("status"))
        for ifname in members:
            res = _member_state(router, ifname, "up", False, True)
            if res:
                return res
    return None


def _drop_mbfd(router, ifname, drop):
    "Drop micro-BFD packets (UDP 6784) leaving `ifname`."
    if drop:
        router.run("tc qdisc add dev {} clsact".format(ifname))
        router.run(
            "tc filter add dev {} egress protocol ip u32 "
            "match ip protocol 17 0xff match ip dport 6784 0xffff "
            "action drop".format(ifname)
        )
    else:
        router.run("tc qdisc del dev {} clsact".format(ifname))


def _zebra_fail_mode(router, mode):
    out = router.vtysh_cmd("show interface bond0")
    if "fail-{}".format(mode) in out:
        return None
    return "{}: zebra registration not fail-{}: {}".format(
        router.name, mode, [l for l in out.splitlines() if "micro-BFD" in l]
    )


def _conf(router, *lines):
    router.vtysh_cmd(
        "configure terminal\nbfd\nlag bond0\n{}\n".format("\n".join(lines))
    )


def test_sessions_up():
    "Sessions Up; failure-mode reaches zebra on both ends."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _expect(_all_up, tgen, count=90)

    assert _lag(r1)["failureMode"] == "closed"
    assert _lag(r2)["failureMode"] == "open"
    assert _lag(r2)["adminDownHold"] == 0
    _expect(_zebra_fail_mode, r1, "closed", count=10)
    _expect(_zebra_fail_mode, r2, "open", count=10)


def test_failure_mode_runtime_change():
    "A failure-mode change re-registers in place; members don't move."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    before = {i: _member(r1, i)["attachCount"] for i in MEMBERS["r1"]}
    _conf(r1, "failure-mode open")
    _expect(_zebra_fail_mode, r1, "open", count=10)
    _conf(r1, "failure-mode closed")
    _expect(_zebra_fail_mode, r1, "closed", count=10)
    _expect(_all_up, tgen, count=10)
    for ifname in MEMBERS["r1"]:
        assert _member(r1, ifname)["attachCount"] == before[ifname]
    assert "failure-mode closed" in r1.vtysh_cmd("show running-config")


def test_failure_mode_closed():
    "bfdd killed with a member out: the member stays out until bfdd decides."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _drop_mbfd(r2, "r2-eth1", True)
    _expect(_member_state, r1, "r1-eth1", None, True, False)

    kill_router_daemons(tgen, "r1", ["bfdd"])
    # failure-mode closed: zebra keeps it out.
    topotest.sleep(5, "bfdd gone, failure-mode closed")
    assert _master(r1, "r1-eth1") == "", "r1-eth1 put back without bfdd"
    assert _master(r1, "r1-eth0") == "bond0"

    start_router_daemons(tgen, "r1", ["bfdd"])
    # Back: the failure is still there, the member stays out.
    _expect(_member_state, r1, "r1-eth0", "up", False)
    _expect(_member_state, r1, "r1-eth1", None, True, False)
    topotest.sleep(5, "past enable-grace")
    assert _master(r1, "r1-eth1") == "", "r1-eth1 put back while its session is down"

    _drop_mbfd(r2, "r2-eth1", False)
    _expect(_all_up, tgen, count=90)


def test_admin_down_hold():
    "Peer AdminDown keeps members in for admin-down-hold, then takes them out."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Long enough to be seen on a slow host.
    _conf(r2, "admin-down-hold 20000")
    _conf(r1, "shutdown")

    def _held():
        members = _lag(r2).get("members", {})
        for ifname in MEMBERS["r2"]:
            m = members.get(ifname, {})
            s = m.get("microBfdIpv4", {})
            if m.get("reason") != "peer signalled AdminDown" or m.get("detached"):
                return "{}: {}".format(ifname, m.get("reason"))
            if not s.get("adminDownHoldRemaining"):
                return "{}: no hold running".format(ifname)
        return None

    _expect(_held, count=15, wait=0.5)

    # The hold ends: out, with the reason.
    for ifname in MEMBERS["r2"]:
        _expect(_member_state, r2, ifname, "down", True, count=60)
        m = _member(r2, ifname)
        assert m["reason"] == "peer AdminDown, hold expired", m
        assert m["microBfdIpv4"]["adminDownHoldExpired"], m

    # 0: as long as AdminDown lasts; members go back in. r1 deleted its
    # sessions once LACP stopped there (RFC 7130, Section 3), and sends
    # AdminDown again when the member distributes again.
    _conf(r2, "admin-down-hold 0")

    def _back_admin_down(ifname):
        err = _member_state(r2, ifname, "down", False)
        if err:
            return err
        reason = _member(r2, ifname).get("reason")
        if reason != "peer signalled AdminDown":
            return "{}: reason {!r}".format(ifname, reason)
        return None

    for ifname in MEMBERS["r2"]:
        _expect(_back_admin_down, ifname, count=60)

    # A new value applies to the hold already running: it started more than
    # 2 s ago, so 2000 ends it at once.
    topotest.sleep(2, "AdminDown older than 2 s")
    _conf(r2, "admin-down-hold 2000")
    for ifname in MEMBERS["r2"]:
        _expect(_member_state, r2, ifname, "down", True, count=20)

    # r1 runs no sessions on members that don't distribute; r2's recovery
    # probe puts its members back.
    _conf(r1, "no shutdown")
    _expect(_all_up, tgen, count=150)
    _conf(r2, "no admin-down-hold")
    assert _lag(r2)["adminDownHold"] == 0


def test_xor_warning():
    "failure-mode open on a balance-xor bond is warned about."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    r1.run("ip link add bond9 type bond mode balance-xor")
    r1.run("ip link set bond9 up")
    r1.vtysh_cmd(
        "configure terminal\nbfd\nlag bond9\nipv4 dest-addr 10.0.41.2 source-addr 10.0.41.1\n"
    )

    def _warned(want):
        lag = _lag(r1, "bond9")
        if lag.get("status") != "ok":
            return "bond9 status {}".format(lag.get("status"))
        if ("failureModeWarning" in lag) != want:
            return "bond9 warning {}".format(lag.get("failureModeWarning"))
        return None

    _expect(_warned, True, count=20)
    assert "failure-mode open on a balance-xor bond" in r1.vtysh_cmd("show bfd lag bond9")
    r1.vtysh_cmd("configure terminal\nbfd\nlag bond9\nfailure-mode closed\n")
    _expect(_warned, False, count=10)

    r1.vtysh_cmd("configure terminal\nbfd\nno lag bond9\n")
    r1.run("ip link del bond9")
    _expect(_all_up, tgen, count=30)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
