#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bfd_lag_topo2.py
#
# Copyright (C) 2026 Aviz Networks
#
# RFC 7130 micro-BFD in both address families between two FRR routers over
# a two-member bond:
#
#   r1 [bond0: r1-eth0, r1-eth1] ===== [bond0: r2-eth0, r2-eth1] r2
#
# - an IPv4 and an IPv6 session per member come Up, members stay in the
#   bond; the IPv6 sessions use the bond's global address;
# - IPv6 micro-BFD packets lost on one member: the member is taken out even
#   though its IPv4 session stays Up (a member carries traffic only while
#   all its sessions are Up), and put back when they flow again;
# - the same with IPv4 packets lost;
# - IPv6 configured on a bond without a global IPv6 address: the IPv6
#   sessions don't run and members are judged on IPv4 alone; they start
#   once the address is there;
# - a link-local destination is refused.
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
ADDR6 = {"r1": "2001:db8:40::1", "r2": "2001:db8:40::2"}
FAMILIES = ("microBfdIpv4", "microBfdIpv6")


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
        # Addresses usable at once, also when added again later.
        router.run("sysctl -qw net.ipv6.conf.bond0.accept_dad=0")
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
        lines.append("===== {} ip -6 addr show dev bond0".format(rname))
        lines.append(router.run("ip -6 addr show dev bond0"))
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


def _member_state(router, ifname, states=None, detached=None, distributing=None):
    """
    `states`: {family key: expected localState, or None for no session}.
    """
    m = _member(router, ifname)
    if not m:
        return "{}: {} not reported".format(router.name, ifname)
    for fam, want in (states or {}).items():
        got = m.get(fam, {}).get("localState")
        if got != want:
            return "{}: {} {} {}, expected {}".format(
                router.name, ifname, fam, got, want
            )
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


BOTH_UP = {"microBfdIpv4": "up", "microBfdIpv6": "up"}


def _all_up(tgen, states=None):
    states = BOTH_UP if states is None else states
    for rname, members in MEMBERS.items():
        router = tgen.gears[rname]
        lag = _lag(router)
        if lag.get("status") != "ok":
            return "{}: lag status {}".format(rname, lag.get("status"))
        for ifname in members:
            res = _member_state(router, ifname, states, False, True)
            if res:
                return res
    return None


def _drop_mbfd(router, ifname, family, drop):
    "Drop micro-BFD packets (UDP 6784) of one family leaving `ifname`."
    if drop:
        router.run("tc qdisc add dev {} clsact 2>/dev/null".format(ifname))
        if family == 6:
            match = "protocol ipv6 u32 match ip6 protocol 17 0xff match ip6 dport 6784 0xffff"
        else:
            match = "protocol ip u32 match ip protocol 17 0xff match ip dport 6784 0xffff"
        router.run(
            "tc filter add dev {} egress {} action drop".format(ifname, match)
        )
    else:
        router.run("tc qdisc del dev {} clsact".format(ifname))


def test_sessions_up():
    "An IPv4 and an IPv6 session per member come Up; members stay in."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    _expect(_all_up, tgen, count=90)

    lag = _lag(r1)
    assert lag["useIpv4"] and lag["useIpv6"], lag
    assert lag["ipv6DestAddr"] == "2001:db8:40::2", lag
    # RFC 7130, Section 2.1: the bond's global address, not link-local.
    assert lag["ipv6SourceAddrInUse"] == ADDR6["r1"], lag
    assert lag["ipv4NoSessionReason"] == "" and lag["ipv6NoSessionReason"] == "", lag

    m = _member(r1, "r1-eth0")
    assert m["microBfdIpv6"]["sourcePort"] >= 49152, m
    # Each family has its own session: own discriminator and source port.
    assert (
        m["microBfdIpv4"]["localDiscriminator"]
        != m["microBfdIpv6"]["localDiscriminator"]
    ), m

    stats = json.loads(r1.vtysh_cmd("show bfd lag statistics json"))
    assert stats["microBfdIpv4SessionStatistics"]["numberOfSessionsUp"] == 2, stats
    assert stats["microBfdIpv6SessionStatistics"]["numberOfSessionsUp"] == 2, stats

    peers = json.loads(r1.vtysh_cmd("show bfd peers json"))
    v6 = [
        p
        for p in peers
        if p.get("bfdMode") == "micro-bfd" and p.get("peer") == "2001:db8:40::2"
    ]
    assert sorted(p["interface"] for p in v6) == ["r1-eth0", "r1-eth1"], peers
    for p in v6:
        assert p["remote-echo-receive-interval"] == 0, p


def test_steady_state():
    "Packets read are the peer's, on their member and family."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    before = {i: _member(r1, i) for i in MEMBERS["r1"]}
    topotest.sleep(3, "steady state")
    for ifname in MEMBERS["r1"]:
        m = _member(r1, ifname)
        assert m["rxWrongDiscriminator"] == before[ifname]["rxWrongDiscriminator"], m
        assert m["rxMismatch"] == before[ifname]["rxMismatch"], m
        assert m["rxBadFrame"] == 0, m
        for fam in FAMILIES:
            assert (
                m[fam]["controlPacketInputCount"]
                > before[ifname][fam]["controlPacketInputCount"]
            ), (fam, m)


def _family_failure(tgen, family, fam_key, other_key):
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    _drop_mbfd(r2, "r2-eth1", family, True)

    _expect(_member_state, r1, "r1-eth1", {fam_key: "down"}, True, False)
    m = _member(r1, "r1-eth1")
    assert m["reason"] == "IPv{} session down".format(family), m
    # The other family's session on that member runs on, Up.
    _expect(_member_state, r1, "r1-eth1", {other_key: "up"})
    # The other member keeps the bond up.
    _expect(_member_state, r1, "r1-eth0", BOTH_UP, False, True)
    if r1.run("command -v ping").strip():
        assert r1.run("ping -c 2 -W 1 10.0.40.2 >/dev/null && echo ok").strip() == "ok"

    _drop_mbfd(r2, "r2-eth1", family, False)
    _expect(_all_up, tgen, count=90)


def test_ipv6_failure_detaches():
    "IPv6 packets lost: the member is out although IPv4 is Up; back after."
    tgen = get_topogen()
    _skip(tgen)
    _family_failure(tgen, 6, "microBfdIpv6", "microBfdIpv4")


def test_ipv4_failure_detaches():
    "IPv4 packets lost: the member is out although IPv6 is Up; back after."
    tgen = get_topogen()
    _skip(tgen)
    _family_failure(tgen, 4, "microBfdIpv4", "microBfdIpv6")


def test_no_ipv6_address():
    "No global IPv6 address: IPv6 left out of the decision, then started."
    tgen = get_topogen()
    _skip(tgen)

    before = {
        (rname, ifname): _member(tgen.gears[rname], ifname)["detachCount"]
        for rname, members in MEMBERS.items()
        for ifname in members
    }
    # r1 first: r2's IPv6 sessions see AdminDown, not a timeout.
    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        router.vtysh_cmd(
            "configure terminal\ninterface bond0\nno ipv6 address {}/64\n".format(
                ADDR6[rname]
            )
        )

    def _v6_gone():
        for rname in ("r1", "r2"):
            lag = _lag(tgen.gears[rname])
            if lag.get("ipv6NoSessionReason") != "no IPv6 source address":
                return "{}: {}".format(rname, lag.get("ipv6NoSessionReason"))
        return None

    # The address is given up a few seconds after it goes.
    _expect(_v6_gone, count=30)
    _expect(_all_up, tgen, {"microBfdIpv4": "up", "microBfdIpv6": None})
    for rname, members in MEMBERS.items():
        for ifname in members:
            m = _member(tgen.gears[rname], ifname)
            assert m["detachCount"] == before[(rname, ifname)], m
    assert tgen.gears["r1"].vtysh_cmd(
        "show bfd lag bond0"
    ).count("ipv6: destination 2001:db8:40::2") == 1

    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        router.vtysh_cmd(
            "configure terminal\ninterface bond0\nipv6 address {}/64\n".format(
                ADDR6[rname]
            )
        )
    _expect(_all_up, tgen, count=90)
    assert _lag(tgen.gears["r1"])["ipv6SourceAddrInUse"] == ADDR6["r1"]


def test_link_local_refused():
    "A link-local destination is refused by the configuration."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    out = r1.vtysh_cmd("configure terminal\nbfd\nlag bond0\nipv6 dest-addr fe80::2\n")
    assert "link-local" in out, out
    assert _lag(r1)["ipv6DestAddr"] == "2001:db8:40::2"
    _expect(_all_up, tgen, count=10)


def test_ipv6_removed():
    "no ipv6: IPv6 sessions go, members stay in on IPv4."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    for router in (r1, r2):
        router.vtysh_cmd("configure terminal\nbfd\nlag bond0\nno ipv6\n")
    _expect(_all_up, tgen, {"microBfdIpv4": "up", "microBfdIpv6": None}, count=20)
    stats = json.loads(r1.vtysh_cmd("show bfd lag statistics json"))
    assert stats["microBfdIpv6SessionStatistics"]["numberOfSessions"] == 0, stats
    assert "ipv6 dest-addr" not in r1.vtysh_cmd("show running-config")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
