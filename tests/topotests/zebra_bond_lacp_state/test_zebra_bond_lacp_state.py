#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_bond_lacp_state.py
#
# Copyright (C) 2026 Aviz Networks
#
# Check that zebra tracks the LACP actor operational state of 802.3ad bond
# members and shows it in "show interface":
#
#   r1 [bond0: r1-eth0, r1-eth1] ===== [bond0: r2-eth0, r2-eth1] r2
#
# - both members reach Collecting + Distributing;
# - when the peer's member goes down, our member stops distributing;
# - when it comes back, it distributes again;
# - a member released from the bond no longer reports a state;
# - a member of a non-LACP (balance-xor) bond reports no state.
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
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = []

DISTRIBUTING = 0x20
COLLECTING = 0x10


def build_topo(tgen):
    "Two routers joined by two links."
    for rname in ("r1", "r2"):
        tgen.add_router(rname)
    for i in range(2):
        switch = tgen.add_switch("s{}".format(i + 1))
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])


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
        for member in ("{}-eth0".format(rname), "{}-eth1".format(rname)):
            router.run("ip link set {} down".format(member))
            router.run("ip link set {} master bond0".format(member))
        router.run("ip link set bond0 up")

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Tear down the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _skip_without_bonding(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if not _have_bonding(tgen.gears["r1"]):
        pytest.skip("kernel has no bonding support")


def _intf_json(router, ifname):
    out = router.vtysh_cmd("show interface {} json".format(ifname))
    return json.loads(out).get(ifname, {})


def _check_state(router, ifname, valid, bits_set=0, bits_clear=0):
    """None when zebra's view of the member's LACP actor state matches."""
    intf = _intf_json(router, ifname)
    if not valid:
        if "lacpActorState" in intf:
            return "{}: unexpected lacpActorState {}".format(
                ifname, intf["lacpActorState"]
            )
        return None
    state = intf.get("lacpActorState")
    if state is None:
        return "{}: no lacpActorState".format(ifname)
    if state & bits_set != bits_set:
        return "{}: state 0x{:02x} missing 0x{:02x}".format(ifname, state, bits_set)
    if state & bits_clear:
        return "{}: state 0x{:02x} has 0x{:02x}".format(ifname, state, bits_clear)
    if intf.get("lacpDistributing") != bool(state & DISTRIBUTING):
        return "{}: lacpDistributing inconsistent with 0x{:02x}".format(ifname, state)
    return None


def _expect_state(router, ifname, **kwargs):
    test_func = functools.partial(_check_state, router, ifname, **kwargs)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_members_distributing():
    "Both members reach Collecting + Distributing."
    tgen = get_topogen()
    _skip_without_bonding(tgen)
    r1 = tgen.gears["r1"]

    for member in ("r1-eth0", "r1-eth1"):
        _expect_state(r1, member, valid=True, bits_set=COLLECTING | DISTRIBUTING)

    out = r1.vtysh_cmd("show interface r1-eth0")
    assert "LACP actor state: 0x" in out, out
    assert "Distributing" in out, out


def test_peer_member_down():
    "The member stops distributing when the peer's member goes down."
    tgen = get_topogen()
    _skip_without_bonding(tgen)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Shut r2-eth1")
    r2.run("ip link set r2-eth1 down")
    _expect_state(r1, "r1-eth1", valid=True, bits_clear=DISTRIBUTING)
    _expect_state(r1, "r1-eth0", valid=True, bits_set=DISTRIBUTING)

    step("Bring r2-eth1 back")
    r2.run("ip link set r2-eth1 up")
    _expect_state(r1, "r1-eth1", valid=True, bits_set=COLLECTING | DISTRIBUTING)


def test_member_released():
    "A member released from the bond no longer reports a state."
    tgen = get_topogen()
    _skip_without_bonding(tgen)
    r1 = tgen.gears["r1"]

    step("Release r1-eth1 from bond0")
    r1.run("ip link set r1-eth1 nomaster")
    _expect_state(r1, "r1-eth1", valid=False)

    step("Enslave it again")
    r1.run("ip link set r1-eth1 down")
    r1.run("ip link set r1-eth1 master bond0")
    _expect_state(r1, "r1-eth1", valid=True, bits_set=COLLECTING | DISTRIBUTING)


def test_non_lacp_bond():
    "A member of a balance-xor bond reports no LACP state."
    tgen = get_topogen()
    _skip_without_bonding(tgen)
    r1 = tgen.gears["r1"]

    r1.run("ip link add v1 type veth peer name v1p")
    r1.run("ip link add bond9 type bond mode balance-xor")
    r1.run("ip link set v1 master bond9")
    r1.run("ip link set bond9 up")
    r1.run("ip link set v1p up")

    def _known():
        return (
            None if _intf_json(r1, "v1").get("masterInterface") == "bond9" else "wait"
        )

    _, result = topotest.run_and_expect(_known, None, count=20, wait=0.5)
    assert result is None, "v1 not seen as bond9 member"
    assert _check_state(r1, "v1", valid=False) is None


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
