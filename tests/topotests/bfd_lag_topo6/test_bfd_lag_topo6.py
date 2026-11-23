#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_lag_topo6.py
#
# Copyright (C) 2026 Aviz Networks
#
# BFD over the bond (BLB) together with RFC 7130 micro-BFD, inherit mode
# ("bundle coexistence bob-blb inherit"):
#
#   r1 [bond0: r1-eth0, r1-eth1] ===== [bond0: r2-eth0, r2-eth1] r2
#
# Each end runs micro-BFD on both members (200 ms x 3) and has a BFD peer
# on bond0. In inherit mode that peer is a virtual session:
#
# - it comes Up from micro-BFD and sends no packets on UDP 3784;
# - one link fails silently: micro-BFD holds the member, the BLB session
#   stays Up;
# - with the bond's min_links at 2 the same failure takes it Down with diag
#   concatenated path down, and it comes back with the member;
# - a peer that runs a real BLB session (logical mode) is reported as a peer
#   mismatch, not answered;
# - removing the command makes it a real session again.
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


def _blb_peer(router, counters=False):
    "The BLB session, from show bfd peers [counters] json."
    cmd = "show bfd peers counters json" if counters else "show bfd peers json"
    try:
        peers = json.loads(router.vtysh_cmd(cmd))
    except ValueError:
        return {}
    for p in peers:
        if p.get("peer") == PEER[router.name] and p.get("interface") == "bond0":
            return p
    return {}


def _set_mode(router, mode):
    if mode:
        router.vtysh_cmd(
            "configure terminal\nbfd\nbundle coexistence bob-blb {}\n".format(mode)
        )
    else:
        router.vtysh_cmd("configure terminal\nbfd\nno bundle coexistence bob-blb\n")


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


def _blb_status(tgen, status, rnames=("r1", "r2")):
    for rname in rnames:
        p = _blb_peer(tgen.gears[rname])
        if p.get("status") != status:
            return "{}: BLB session {} (want {})".format(rname, p.get("status"), status)
    return None


def _inherited(tgen, members_up, min_links=1):
    "Both ends: virtual, following IPv4, aggregate as given."
    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        lag = _lag(router)
        if lag.get("blbMode") != "inherit":
            return "{}: blbMode {}".format(rname, lag.get("blbMode"))
        agg = lag.get("blbAggregate", {}).get("ipv4", {})
        if agg.get("membersUp") != members_up:
            return "{}: aggregate {}".format(rname, agg)
        s = lag.get("blbSessions", {}).get(PEER[rname], {})
        if s.get("virtual") is not True or s.get("follows") != "ipv4":
            return "{}: BLB session in show bfd lag {}".format(rname, s)
        b = _blb_peer(router).get("blb", {})
        if (
            b.get("mode") != "inherit"
            or b.get("virtual") is not True
            or b.get("minLinks") != min_links
        ):
            return "{}: blb in show bfd peers {}".format(rname, b)
    return None


def _drop_link(tgen, idx, drop):
    """
    Silent failure of link `idx` in both directions: r1 drops every IP
    packet it sends or receives on its member, in one command, so both
    directions fail at the same moment (two commands one after the other
    leave a one-way window that can be seconds long on a loaded host).
    """
    router = tgen.gears["r1"]
    ifname = MEMBERS["r1"][idx]
    if drop:
        router.run(
            "tc qdisc add dev {0} clsact && "
            "tc filter add dev {0} egress protocol ip u32 match u32 0 0 action drop && "
            "tc filter add dev {0} ingress protocol ip u32 match u32 0 0 action drop".format(
                ifname
            )
        )
    else:
        router.run("tc qdisc del dev {} clsact".format(ifname))


def _detach_count(tgen, rname, idx=0):
    m = _lag(tgen.gears[rname]).get("members", {}).get(MEMBERS[rname][idx], {})
    return m.get("detachCount", 0)


def _set_min_links(tgen, n):
    for router in tgen.routers().values():
        router.run("ip link set bond0 type bond min_links {}".format(n))

    def _seen():
        for rname in ("r1", "r2"):
            got = _lag(tgen.gears[rname]).get("minLinks")
            if got != n:
                return "{}: minLinks {} (want {})".format(rname, got, n)
        return None

    _expect(_seen, count=20)


def test_sessions_up():
    "micro-BFD comes Up and the BLB session inherits Up, virtual on both ends."
    tgen = get_topogen()
    _skip(tgen)

    _expect(_micro_up, tgen)
    _expect(_blb_status, tgen, "up")
    _expect(_inherited, tgen, 2, count=10)

    out = tgen.gears["r1"].vtysh_cmd("show running-config bfdd")
    assert "bundle coexistence bob-blb inherit" in out, out
    out = tgen.gears["r1"].vtysh_cmd("show bfd peers")
    assert "BLB: inherited from lag bond0 (virtual, no packets" in out, out


def test_no_packets():
    "A virtual session sends no control packets."
    tgen = get_topogen()
    _skip(tgen)

    before = {
        rname: _blb_peer(tgen.gears[rname], True).get("control-packet-output")
        for rname in ("r1", "r2")
    }
    topotest.sleep(3, "letting a would-be BLB session transmit")
    for rname in ("r1", "r2"):
        now = _blb_peer(tgen.gears[rname], True).get("control-packet-output")
        assert now == before[rname], "{}: BLB sent packets ({} -> {})".format(
            rname, before[rname], now
        )


def test_member_failure():
    "A silent link failure: micro-BFD holds the member, BLB stays Up."
    tgen = get_topogen()
    _skip(tgen)

    downs = {
        rname: _blb_peer(tgen.gears[rname], True).get("session-down")
        for rname in ("r1", "r2")
    }
    held = {rname: _detach_count(tgen, rname) for rname in ("r1", "r2")}

    _drop_link(tgen, 0, True)

    def _held():
        for rname in ("r1", "r2"):
            if _detach_count(tgen, rname) <= held[rname]:
                return "{}: {} not held down".format(rname, MEMBERS[rname][0])
        return None

    _expect(_held, count=30)
    _expect(_blb_status, tgen, "up", count=5)
    for rname in ("r1", "r2"):
        now = _blb_peer(tgen.gears[rname], True).get("session-down")
        assert now == downs[rname], "{}: BLB went down ({} -> {})".format(
            rname, downs[rname], now
        )

    _drop_link(tgen, 0, False)
    _expect(_micro_up, tgen, count=90)
    _expect(_inherited, tgen, 2, count=10)


def test_min_links():
    "min_links 2: one failed member takes BLB Down, concatenated path down."
    tgen = get_topogen()
    _skip(tgen)

    _set_min_links(tgen, 2)
    _expect(_inherited, tgen, 2, 2, count=10)
    _expect(_blb_status, tgen, "up", count=5)

    _drop_link(tgen, 0, True)
    _expect(_blb_status, tgen, "down", count=30)
    for rname in ("r1", "r2"):
        p = _blb_peer(tgen.gears[rname])
        assert p.get("diagnostic") == "concatenated path down", "{}: {}".format(
            rname, p.get("diagnostic")
        )

    _drop_link(tgen, 0, False)
    _expect(_micro_up, tgen, count=90)
    _expect(_blb_status, tgen, "up", count=10)

    _set_min_links(tgen, 0)
    _expect(_inherited, tgen, 2, 1, count=10)


def test_peer_mismatch():
    "A peer running a real BLB session is reported, not answered."
    tgen = get_topogen()
    _skip(tgen)

    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    _set_mode(r2, "logical")

    def _mismatch(want):
        b = _blb_peer(r1).get("blb", {})
        if b.get("peerMismatch") is not want:
            return "r1: peerMismatch {} (want {}), {}".format(
                b.get("peerMismatch"), want, b
            )
        if want and not b.get("mismatchPackets"):
            return "r1: no mismatch packets counted"
        return None

    _expect(_mismatch, True, count=15)
    # r1 still follows micro-BFD; r2's real session gets no answer.
    _expect(_blb_status, tgen, "up", ("r1",), count=5)
    _expect(_blb_status, tgen, "down", ("r2",), count=10)
    out = r1.vtysh_cmd("show bfd peers")
    assert "PEER MISMATCH" in out, out

    _set_mode(r2, "inherit")
    _expect(_blb_status, tgen, "up", count=10)
    # The mark clears 10 s after the last packet.
    _expect(_mismatch, False, count=20)


def test_mode_removed():
    "Without the command the BLB session is a real session again."
    tgen = get_topogen()
    _skip(tgen)

    sent = _blb_peer(tgen.gears["r1"], True).get("control-packet-output")
    for router in tgen.routers().values():
        _set_mode(router, None)

    def _real():
        for rname in ("r1", "r2"):
            router = tgen.gears[rname]
            if _lag(router).get("blbMode") != "none":
                return "{}: blbMode {}".format(rname, _lag(router).get("blbMode"))
            if "blb" in _blb_peer(router):
                return "{}: blb still in show bfd peers".format(rname)
        return None

    _expect(_real, count=10)
    _expect(_blb_status, tgen, "up", count=15)
    now = _blb_peer(tgen.gears["r1"], True).get("control-packet-output")
    assert now > sent, "r1: real BLB session sends nothing ({} -> {})".format(sent, now)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
