#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_lag_topo4.py
#
# Copyright (C) 2026 Aviz Networks
#
# RFC 7130 micro-BFD in distributing-only mode, between two FRR routers over
# a two-member bond, both ends distributing-only:
#
#   r1 [bond0: r1-eth0, r1-eth1] ===== [bond0: r2-eth0, r2-eth1] r2
#
# - sessions run on the distributing members and come Up;
# - LACP taking a member out (LACPDUs lost) is no micro-BFD failure: no
#   detach, its sessions are deleted (RFC 7130, Section 3) and start again
#   when it distributes; the same on carrier loss. When LACP fails on one
#   side only, the end still distributing loses its sessions and takes the
#   member out; its recovery probe puts it back once LACP works again;
# - sessions that were Up go Down: the member is taken out, its sessions
#   keep running, and it goes back when they are Up;
# - sessions that never come Up: the member stays in with max-setup-time
#   0, and is taken out when it has distributed for max-setup-time;
# - the peer's bfdd restarting (all members taken out there) recovers.
# - a mode change restarts the LAG: a member micro-BFD took out is put back.
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


def _check(router, ifname, state=None, detached=None, active=None, reason=None):
    """
    state: session localState, "none" for no session; detached: micro-BFD
    took it out (and the kernel agrees); active: sessions running; reason.
    """
    m = _member(router, ifname)
    if not m:
        return "{}: {} not reported".format(router.name, ifname)
    got = m.get("microBfdIpv4", {}).get("localState", "none")
    if state is not None and got != state:
        return "{}: {} session {}, expected {}".format(router.name, ifname, got, state)
    if active is not None and m.get("sessionActive") != active:
        return "{}: {} sessionActive={}".format(router.name, ifname, m.get("sessionActive"))
    if reason is not None and m.get("reason") != reason:
        return "{}: {} reason {!r}, expected {!r}".format(
            router.name, ifname, m.get("reason"), reason
        )
    if detached is not None:
        if m.get("detached") != detached:
            return "{}: {} detached={} (reason {!r})".format(
                router.name, ifname, m.get("detached"), m.get("reason")
            )
        kernel = _master(router, ifname)
        if detached and kernel != "":
            return "{}: {} still in {}".format(router.name, ifname, kernel)
        if not detached and kernel != "bond0":
            return "{}: {} not in bond0 ({!r})".format(router.name, ifname, kernel)
    return None


def _all_up(tgen):
    for rname, members in MEMBERS.items():
        router = tgen.gears[rname]
        for ifname in members:
            res = _check(router, ifname, "up", False, True)
            if res:
                return res
            if not _member(router, ifname).get("distributing"):
                return "{}: {} not distributing".format(rname, ifname)
    return None


def _tc(router, ifname, what):
    "Drop LACPDUs ('lacp') or micro-BFD ('mbfd') leaving ifname; 'off' clears."
    if what == "off":
        router.run("tc qdisc del dev {} clsact 2>/dev/null".format(ifname))
        return
    router.run("tc qdisc add dev {} clsact 2>/dev/null".format(ifname))
    if what == "lacp":
        match = "pref 1 protocol 0x8809 u32 match u32 0 0"
    else:
        match = "pref 2 protocol ip u32 match ip protocol 17 0xff match ip dport 6784 0xffff"
    router.run("tc filter add dev {} egress {} action drop".format(ifname, match))


def _detaches(router):
    return sum(m.get("detachCount", 0) for m in _lag(router).get("members", {}).values())


def _conf(router, *lines):
    return router.vtysh_cmd(
        "configure terminal\nbfd\nlag bond0\n{}\n".format("\n".join(lines))
    )


def test_sessions_up():
    "Sessions on the distributing members come Up; mode shown."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    _expect(_all_up, tgen, count=90)
    lag = _lag(r1)
    assert lag["mode"] == "distributing-only", lag
    assert lag["maxSetupTime"] == 0, lag
    out = r1.vtysh_cmd("show bfd lag bond0")
    assert "enable-grace 3000 ms (not used in this mode)" in out, out
    assert "not RFC 7130 strict" in out, out


def _not_distributing(router, ifname):
    if _member(router, ifname).get("distributing"):
        return "{}: {} still distributing".format(router.name, ifname)
    return None


def test_lacp_removal_is_not_a_failure():
    """
    LACP takes a member out: no detach, its sessions are deleted.

    r2's LACPDUs are lost: r1-eth1 stops distributing, while r2-eth1 may
    keep distributing (r1 still reports sync). r2 then loses its sessions on
    a member it sends on, and takes it out: that's the RFC behaviour, r1
    doesn't collect there. Its recovery probe puts it back.
    """
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    d1 = _detaches(r1)
    _tc(r2, "r2-eth1", "lacp")
    _expect(_not_distributing, r1, "r1-eth1", count=30)
    # RFC 7130, Section 3: not distributing, no sessions; still in the bond.
    _expect(
        _check, r1, "r1-eth1", "none", False, False, "not distributing (no sessions)", count=30
    )
    _expect(_check, r1, "r1-eth0", "up", False, True)
    assert _detaches(r1) == d1

    _tc(r2, "r2-eth1", "off")
    _expect(_all_up, tgen, count=90)
    assert _detaches(r1) == d1


def test_carrier_loss_stops_sessions():
    "A member losing carrier stops its sessions; carrier back starts them."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    d1 = _detaches(r1)
    r2.run("ip link set r2-eth1 down")
    _expect(_check, r1, "r1-eth1", "none", False, False, "not distributing (no sessions)", count=30)
    assert "member r1-eth1: attached, no sessions" in r1.vtysh_cmd("show bfd lag bond0")
    r2.run("ip link set r2-eth1 up")
    _expect(_all_up, tgen, count=60)
    assert _detaches(r1) == d1


def _admin_up(router, ifname):
    try:
        link = json.loads(router.run("ip -j link show dev {}".format(ifname)))[0]
    except (ValueError, IndexError):
        return None
    return "UP" in link.get("flags", [])


def test_admin_down_respected():
    "A member set down on r2: sessions deleted on both ends, it stays down, in bond0."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    d2 = _detaches(r2)
    r2.run("ip link set r2-eth1 down")
    _expect(_check, r2, "r2-eth1", "none", False, False, "not distributing (no sessions)", count=30)
    _expect(_check, r1, "r1-eth1", "none", None, False, count=30)
    topotest.sleep(5, "member stays down")
    assert _admin_up(r2, "r2-eth1") is False, "r2-eth1 set up again"
    assert _master(r2, "r2-eth1") == "bond0"
    assert _detaches(r2) == d2

    r2.run("ip link set r2-eth1 up")
    _expect(_all_up, tgen, count=90)


def _restart_r1_eth1(tgen, mbfd_drop):
    """
    Stop r1-eth1's sessions (carrier lost), then let it come back with
    micro-BFD from r2 lost from the start if `mbfd_drop`.
    """
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r2.run("ip link set r2-eth1 down")
    _expect(_check, r1, "r1-eth1", "none", False, False, count=30)
    if mbfd_drop:
        _tc(r2, "r2-eth1", "mbfd")
    r2.run("ip link set r2-eth1 up")


def test_failure_detaches():
    "Sessions that were Up go Down: out, sessions keep running, back after."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _tc(r2, "r2-eth1", "mbfd")
    _expect(_check, r1, "r1-eth1", "down", True, True, "session down", count=30)
    # Out of the bond, the sessions still run (they decide when it goes back).
    topotest.sleep(3, "detached member keeps its sessions")
    assert _check(r1, "r1-eth1", None, True, True) is None

    _tc(r2, "r2-eth1", "off")
    _expect(_all_up, tgen, count=90)
    assert _member(r1, "r1-eth1")["attachCount"] >= 1


def test_max_setup_time():
    "Sessions that never come Up: in with max-setup-time 0, out once it's over."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # max-setup-time 0: the member waits, in the bond.
    _restart_r1_eth1(tgen, True)
    _expect(
        _check, r1, "r1-eth1", "down", False, True,
        "waiting for session (max-setup-time off)", count=60,
    )
    topotest.sleep(5, "no limit: stays in")
    assert _check(r1, "r1-eth1", "down", False, True) is None
    _tc(r2, "r2-eth1", "off")
    _expect(_all_up, tgen, count=60)

    # max-setup-time 3000, from the next start.
    _conf(r1, "max-setup-time 3000")
    _restart_r1_eth1(tgen, True)
    _expect(
        _check, r1, "r1-eth1", "down", True, True, "max-setup-time expired", count=60,
    )
    assert _member(r1, "r1-eth1")["maxSetupExpired"]

    _tc(r2, "r2-eth1", "off")
    _expect(_all_up, tgen, count=90)
    _conf(r1, "no max-setup-time")


def test_peer_bfdd_restart():
    "r2's bfdd killed: r1 takes both members out, r2 comes back, all recover."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    kill_router_daemons(tgen, "r2", ["bfdd"])
    # r1: sessions that were Up went down on distributing members: out.
    for ifname in MEMBERS["r1"]:
        _expect(_check, r1, ifname, "down", True, True, count=30)
    # r2's members lost their LACP partner and run no sessions when its
    # bfdd is back; r1 hears nothing on the members it keeps out, and its
    # recovery probe puts them back: everything recovers.
    start_router_daemons(tgen, "r2", ["bfdd"])
    _expect(_all_up, tgen, count=180)
    assert sum(_member(r1, i).get("probeCount", 0) for i in MEMBERS["r1"]) >= 1


def test_mode_change():
    "A mode change restarts the LAG: a member micro-BFD took out goes back."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _tc(r2, "r2-eth1", "mbfd")
    _expect(_check, r1, "r1-eth1", "down", True, True, count=30)
    attached = _member(r1, "r1-eth1")["attachCount"]

    _conf(r1, "mode strict")

    def _put_back():
        m = _member(r1, "r1-eth1")
        if m.get("attachCount", 0) <= attached:
            return "r1-eth1 not put back (attachCount {})".format(m.get("attachCount"))
        return None

    _expect(_put_back, count=30)
    assert _lag(r1)["mode"] == "strict"
    # What follows depends on r2, which took r2-eth1 out too: r1-eth1 only
    # distributes (and runs sessions) once r2's recovery probe puts r2-eth1
    # back. Packets flowing again, everything recovers.
    _tc(r2, "r2-eth1", "off")
    _expect(_all_up, tgen, count=150)
    out = _conf(r1, "max-setup-time 1000")
    assert "used in mode distributing-only only" in out, out
    _conf(r1, "no max-setup-time", "mode distributing-only")
    _expect(_all_up, tgen, count=90)
    assert _lag(r1)["mode"] == "distributing-only"
    assert "  mode distributing-only" in r1.vtysh_cmd("show running-config")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
