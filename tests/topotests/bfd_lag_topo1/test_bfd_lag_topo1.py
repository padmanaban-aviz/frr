#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_lag_topo1.py
#
# Copyright (C) 2026 Aviz Networks
#
# RFC 7130 micro-BFD between two FRR routers over a two-member bond:
#
#   r1 [bond0: r1-eth0, r1-eth1] ===== [bond0: r2-eth0, r2-eth1] r2
#
# - one session per member comes Up, members stay in the bond;
# - sessions are Asynchronous only (Required Min Echo RX 0) and marked as
#   micro-BFD in "show bfd peers";
# - micro-BFD packets lost on one member: that member is taken out of the
#   bond (strict mode), the other keeps carrying traffic;
# - packets flow again: the member is put back and distributes again;
# - shutdown is not a failure: no member is taken out, on either end;
# - bfdd stopping puts members back (zebra fail-open); after a restart
#   enable-grace delays the decision, then strict mode applies again;
# - a bond in an unsupported mode runs no sessions.
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
        lag = _lag(router)
        if lag.get("status") != "ok":
            return "{}: lag status {}".format(rname, lag.get("status"))
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


def test_sessions_up():
    "One session per member comes Up; every member stays in the bond."
    tgen = get_topogen()
    _skip(tgen)

    _expect(_all_up, tgen)

    lag = _lag(tgen.gears["r1"])
    assert lag["mode"] == "strict"
    assert lag["ipv4DestAddr"] == "10.0.40.2"
    assert lag["ipv4SourceAddrInUse"] == "10.0.40.1"
    assert lag["profile"] == "lag"
    assert lag["noSessionReason"] == ""


def test_asynchronous_only():
    "Micro-BFD sessions don't ask for echo and are marked in show bfd peers."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    peers = json.loads(r2.vtysh_cmd("show bfd peers json"))
    mbfd = [p for p in peers if p.get("bfdMode") == "micro-bfd"]
    assert sorted(p["interface"] for p in mbfd) == ["r2-eth0", "r2-eth1"], peers
    for p in mbfd:
        assert p["lag"] == "bond0"
        assert p["bfd-name"] == "lag:bond0"
        assert p["peer"] == "10.0.40.1"
        # RFC 7130, Section 2.2: r1 advertises Required Min Echo RX 0.
        assert p["remote-echo-receive-interval"] == 0, p
        assert p["receive-interval"] == 200 and p["transmit-interval"] == 200

    # The packets r1 reads are r2's, on the member they were sent on. A
    # Your Discriminator of an older session can show up right after a
    # session restart; in steady state none does.
    before = {i: _member(r1, i) for i in MEMBERS["r1"]}
    topotest.sleep(3, "steady state")
    for ifname in MEMBERS["r1"]:
        m = _member(r1, ifname)
        assert m["rxWrongDiscriminator"] == before[ifname]["rxWrongDiscriminator"], m
        assert m["rxMismatch"] == before[ifname]["rxMismatch"], m
        assert m["rxBadFrame"] == 0, m
        assert (
            m["microBfdIpv4"]["controlPacketInputCount"]
            > before[ifname]["microBfdIpv4"]["controlPacketInputCount"]
        ), m

    stats = json.loads(r1.vtysh_cmd("show bfd lag statistics json"))
    assert stats["microBfdIpv4SessionStatistics"]["numberOfSessionsUp"] == 2, stats


def test_member_failure_detaches():
    "Micro-BFD packets lost on one member take it out of the bond."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _drop_mbfd(r2, "r2-eth1", True)

    _expect(_member_state, r1, "r1-eth1", None, True, False)
    assert _member(r1, "r1-eth1")["reason"] == "session down"
    assert _member(r1, "r1-eth1")["detachCount"] >= 1

    # The other member keeps the bond up.
    _expect(_member_state, r1, "r1-eth0", "up", False, True)
    _expect(_member_state, r2, "r2-eth0", "up", False, True)
    if r1.run("command -v ping").strip():
        assert r1.run("ping -c 2 -W 1 10.0.40.2 >/dev/null && echo ok").strip() == "ok"


def test_member_recovery_attaches():
    "Packets flow again: the member goes back into the bond and distributes."
    tgen = get_topogen()
    _skip(tgen)

    _drop_mbfd(tgen.gears["r2"], "r2-eth1", False)

    _expect(_all_up, tgen, count=90)
    assert _member(tgen.gears["r1"], "r1-eth1")["attachCount"] >= 1


def test_all_members_down():
    "Every member out: the bond goes down, sessions keep running and recover."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    for ifname in MEMBERS["r2"]:
        _drop_mbfd(r2, ifname, True)
    for ifname in MEMBERS["r1"]:
        _expect(_member_state, r1, ifname, None, True, False)

    # The bond has no carrier now, and zebra withdraws its addresses from
    # the daemons; the sessions keep the LAG's address.
    lag = _lag(r1)
    assert lag["ipv4SourceAddrInUse"] == "10.0.40.1", lag
    assert lag["noSessionReason"] == "", lag
    for ifname in MEMBERS["r1"]:
        assert _member(r1, ifname)["microBfdIpv4"]["localState"] != "admin-down"

    for ifname in MEMBERS["r2"]:
        _drop_mbfd(r2, ifname, False)
    _expect(_all_up, tgen, count=90)


def test_shutdown_is_not_a_failure():
    "Shutdown on r1: sessions AdminDown on r1, peer AdminDown on r2, no detach."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    before = {i: _member(r2, i)["detachCount"] for i in MEMBERS["r2"]}
    r1.vtysh_cmd("configure terminal\nbfd\nlag bond0\nshutdown\n")

    for ifname in MEMBERS["r1"]:
        _expect(_member_state, r1, ifname, "admin-down", False)
    for ifname in MEMBERS["r2"]:
        _expect(_member_state, r2, ifname, "down", False)
        assert _member(r2, ifname)["reason"] == "peer signalled AdminDown"
        assert _member(r2, ifname)["detachCount"] == before[ifname]

    r1.vtysh_cmd("configure terminal\nbfd\nlag bond0\nno shutdown\n")
    _expect(_all_up, tgen, count=90)
    for ifname in MEMBERS["r2"]:
        assert _member(r2, ifname)["detachCount"] == before[ifname]


def test_bfdd_restart():
    "bfdd going away puts members back; after a restart enable-grace applies."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _drop_mbfd(r2, "r2-eth1", True)
    _expect(_member_state, r1, "r1-eth1", None, True, False)

    kill_router_daemons(tgen, "r1", ["bfdd"])
    # Zebra re-attaches what bfdd took out (fail-open).
    _expect(
        lambda: None if _master(r1, "r1-eth1") == "bond0" else "r1-eth1 not back",
        count=20,
    )

    start_router_daemons(tgen, "r1", ["bfdd"])
    # The failure is still there: after enable-grace, out again.
    _expect(_member_state, r1, "r1-eth1", None, True, False)
    _expect(_member_state, r1, "r1-eth0", "up", False)

    _drop_mbfd(r2, "r2-eth1", False)
    _expect(_all_up, tgen, count=90)


def _admin_up(router, ifname):
    try:
        link = json.loads(router.run("ip -j link show dev {}".format(ifname)))[0]
    except (ValueError, IndexError):
        return None
    return "UP" in link.get("flags", [])


def test_admin_down_respected():
    "A member the operator sets down stays down: micro-BFD doesn't undo it."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    r1.run("ip link set r1-eth1 down")
    # No carrier: sessions down, micro-BFD takes it out of the bond...
    _expect(_member_state, r1, "r1-eth1", None, True, False, count=30)
    # ... but leaves it down.
    topotest.sleep(5, "member stays down")
    assert _admin_up(r1, "r1-eth1") is False, "micro-BFD set r1-eth1 up"
    assert _master(r1, "r1-eth1") == ""

    r1.run("ip link set r1-eth1 up")
    _expect(_all_up, tgen, count=90)


def test_unsupported_mode():
    "A bond zebra can't use for micro-BFD runs no sessions."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    r1.run("ip link add bond9 type bond mode active-backup")
    r1.run("ip link set bond9 up")
    r1.vtysh_cmd(
        "configure terminal\nbfd\nlag bond9\nipv4 dest-addr 10.0.41.2 source-addr 10.0.41.1\n"
    )
    _expect(
        lambda: (
            None
            if _lag(r1, "bond9").get("status") == "unsupported-mode"
            else _lag(r1, "bond9")
        ),
        count=20,
    )
    lag = _lag(r1, "bond9")
    assert lag["members"] == {}
    assert "not supported" in lag["noSessionReason"]

    r1.vtysh_cmd("configure terminal\nbfd\nno lag bond9\n")
    r1.run("ip link del bond9")
    # bond0 is unaffected.
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
