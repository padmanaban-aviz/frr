#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_lag_mbfd.py
#
# Copyright (C) 2026 Aviz Networks
#
# zebra's RFC 7130 micro-BFD bond member API (ZEBRA_LAG_MBFD_*), with
# sharpd playing the client (bfdd):
#
#   r1 [bond0: r1-eth0, r1-eth1] ===== [bond0: r2-eth0, r2-eth1] r2
#
# - registration: bond status ok, both members reported distributing;
# - detach / attach of a member, as seen in the kernel and by the client;
# - carrier loss clears "distributing" at once;
# - unsupported bond mode, and a deleted bond (not-found);
# - a detached member re-enslaved by someone else is released again;
# - fail-open on unregister and when the client goes away;
# - fail-closed keeps the member out, and a new registration reports it;
# - zebra stop (fail-open re-attach), crash (state file re-attach) and
#   restart with fail-closed (member kept out and reported again).
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
from lib.common_config import kill_router_daemons, start_router_daemons, step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.sharpd]


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
        for member in ("{}-eth0".format(rname), "{}-eth1".format(rname)):
            router.run("ip link set {} down".format(member))
            router.run("ip link set {} master bond0".format(member))
        router.run("ip link set bond0 up")

    tgen.gears["r1"].load_frr_config(
        os.path.join(CWD, "r1/frr.conf"), extra_daemons=["sharpd"]
    )
    tgen.gears["r2"].load_frr_config(os.path.join(CWD, "r2/frr.conf"))
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


def _sharp(r1):
    return json.loads(r1.vtysh_cmd("show sharp lag-mbfd json"))


def _master(router, ifname):
    try:
        link = json.loads(router.run("ip -j -d link show dev {}".format(ifname)))[0]
    except (ValueError, IndexError):
        return None
    return link.get("master", "")


def _flags(r1, ifname):
    mbr = _sharp(r1)["members"].get(ifname)
    return set(mbr["flags"].split(",")) - {""} if mbr else None


def _expect(func, *args, count=40, wait=0.5):
    _, result = topotest.run_and_expect(
        functools.partial(func, *args), None, count, wait
    )
    assert result is None, result


def _member_state(r1, ifname, has=(), lacks=(), master=None):
    flags = _flags(r1, ifname)
    if flags is None:
        return "{} not reported".format(ifname)
    missing = set(has) - flags
    extra = set(lacks) & flags
    if missing or extra:
        return "{} flags {}: missing {} unexpected {}".format(
            ifname, flags, missing, extra
        )
    if master is not None and _master(r1, ifname) != master:
        return "{} kernel master {!r}, expected {!r}".format(
            ifname, _master(r1, ifname), master
        )
    return None


def _bond_status(r1, bond, status):
    b = _sharp(r1)["bonds"].get(bond)
    if not b or b["status"] != status:
        return "{} status {}".format(bond, b)
    return None


ATTACHED_OK = ("attached", "distributing", "oper-up", "admin-up", "ad-state-valid")


def test_register():
    "Registration: status ok, both members reported distributing."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("sharp lag-mbfd bond bond0")
    _expect(_bond_status, r1, "bond0", "ok")
    assert _sharp(r1)["bonds"]["bond0"]["mode"] == 4
    for m in ("r1-eth0", "r1-eth1"):
        _expect(
            _member_state, r1, m, ATTACHED_OK, ("mbfd-detached", "pending"), "bond0"
        )


def test_detach_attach():
    "Detach a member, then attach it again."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    step("Detach r1-eth1")
    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 detach")
    _expect(
        _member_state,
        r1,
        "r1-eth1",
        ("mbfd-detached", "admin-up"),
        ("attached", "distributing", "pending"),
        "",
    )
    out = json.loads(r1.vtysh_cmd("show interface r1-eth1 json"))["r1-eth1"]
    assert out["microBfdMember"]["detached"] is True, out
    # The other member keeps distributing.
    _expect(_member_state, r1, "r1-eth0", ATTACHED_OK, (), "bond0")

    step("Attach r1-eth1 again")
    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 attach")
    _expect(
        _member_state, r1, "r1-eth1", ATTACHED_OK, ("mbfd-detached", "pending"), "bond0"
    )


def test_carrier_loss():
    "Carrier loss clears distributing straight away."
    tgen = get_topogen()
    _skip(tgen)
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    r2.run("ip link set r2-eth0 down")
    _expect(
        _member_state,
        r1,
        "r1-eth0",
        ("attached",),
        ("distributing", "oper-up"),
        count=10,
    )
    r2.run("ip link set r2-eth0 up")
    _expect(_member_state, r1, "r1-eth0", ATTACHED_OK, ())


def test_external_reenslave():
    "A detached member put back by someone else is released again."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 detach")
    _expect(_member_state, r1, "r1-eth1", ("mbfd-detached",), ("attached",), "")

    step("Re-enslave r1-eth1 behind zebra's back")
    r1.run("ip link set r1-eth1 down")
    r1.run("ip link set r1-eth1 master bond0")
    _expect(
        _member_state,
        r1,
        "r1-eth1",
        ("mbfd-detached", "ext-reenslaved"),
        ("attached",),
        "",
    )

    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 attach")
    _expect(
        _member_state,
        r1,
        "r1-eth1",
        ATTACHED_OK,
        ("mbfd-detached", "ext-reenslaved"),
        "bond0",
    )


def test_unregister_fail_open():
    "Unregistering re-attaches detached members."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 detach")
    _expect(_member_state, r1, "r1-eth1", ("mbfd-detached",), ("attached",), "")

    r1.vtysh_cmd("no sharp lag-mbfd bond bond0")
    _expect(lambda: None if _master(r1, "r1-eth1") == "bond0" else "not re-attached")


def test_client_gone_fail_open():
    "The client going away re-attaches detached members (fail-open)."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("sharp lag-mbfd bond bond0")
    _expect(_bond_status, r1, "bond0", "ok")
    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 detach")
    _expect(_member_state, r1, "r1-eth1", ("mbfd-detached",), ("attached",), "")

    kill_router_daemons(tgen, "r1", ["sharpd"], save_config=False)
    _expect(lambda: None if _master(r1, "r1-eth1") == "bond0" else "not re-attached")
    start_router_daemons(tgen, "r1", ["sharpd"])


def test_client_gone_fail_closed():
    "Fail-closed keeps the member out; a new registration reports it."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("sharp lag-mbfd bond bond0 fail-closed")
    _expect(_bond_status, r1, "bond0", "ok")
    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 detach")
    _expect(_member_state, r1, "r1-eth1", ("mbfd-detached",), ("attached",), "")

    kill_router_daemons(tgen, "r1", ["sharpd"], save_config=False)
    topotest.sleep(3, "give zebra time to (not) re-attach")
    assert _master(r1, "r1-eth1") == "", "fail-closed member was re-attached"

    start_router_daemons(tgen, "r1", ["sharpd"])
    r1.vtysh_cmd("sharp lag-mbfd bond bond0")
    _expect(_member_state, r1, "r1-eth1", ("mbfd-detached",), ("attached",), "")

    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 attach")
    _expect(_member_state, r1, "r1-eth1", ATTACHED_OK, ("mbfd-detached",), "bond0")


def _zebra_running(r1):
    out = r1.run(
        "p=$(cat /var/run/frr/zebra.pid 2>/dev/null); "
        '[ -n "$p" ] && [ -d /proc/$p ] && echo yes || echo no'
    )
    return out.strip() == "yes"


def _zebra_stop(tgen, r1, signal):
    r1.run("kill -{} $(cat /var/run/frr/zebra.pid)".format(signal))
    _expect(lambda: None if not _zebra_running(r1) else "zebra still running")


def _zebra_start(tgen, r1):
    start_router_daemons(tgen, "r1", ["zebra"])
    _expect(lambda: None if _zebra_running(r1) else "zebra not running")


def _register(r1, extra=""):
    def _try():
        r1.vtysh_cmd("sharp lag-mbfd bond bond0 {}".format(extra))
        return _bond_status(r1, "bond0", "ok")

    _expect(_try, count=30, wait=1)


STATE_FILE = "/var/run/frr/zebra_mbfd.state"


def _state_has(r1, line):
    lines = r1.run("cat {} 2>/dev/null".format(STATE_FILE)).splitlines()
    return None if line in lines else "{!r} not in state file {}".format(line, lines)


def test_zebra_stop_fail_open():
    "zebra stopping (SIGTERM) re-attaches fail-open members on its way out."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    _register(r1)
    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 detach")
    _expect(_member_state, r1, "r1-eth1", ("mbfd-detached",), ("attached",), "")

    _zebra_stop(tgen, r1, "TERM")
    assert _master(r1, "r1-eth1") == "bond0", "not re-attached at zebra shutdown"
    _zebra_start(tgen, r1)


def test_zebra_crash_fail_open():
    "After a zebra crash, the state file re-attaches fail-open members."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    _register(r1)
    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 detach")
    _expect(_member_state, r1, "r1-eth1", ("mbfd-detached",), ("attached",), "")

    _expect(_state_has, r1, "r1-eth1 bond0 1")

    _zebra_stop(tgen, r1, "KILL")
    assert _master(r1, "r1-eth1") == "", "re-attached without zebra"
    _zebra_start(tgen, r1)
    _expect(
        lambda: None if _master(r1, "r1-eth1") == "bond0" else "not re-attached",
        count=60,
        wait=1,
    )


def test_zebra_stop_fail_closed():
    "Fail-closed members stay out across a zebra restart."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    _register(r1, "fail-closed")
    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 detach")
    _expect(_member_state, r1, "r1-eth1", ("mbfd-detached",), ("attached",), "")
    _expect(_state_has, r1, "r1-eth1 bond0 0")

    _zebra_stop(tgen, r1, "TERM")
    assert _master(r1, "r1-eth1") == "", "fail-closed member re-attached"
    _zebra_start(tgen, r1)
    topotest.sleep(8, "let zebra read its state file")
    assert _master(r1, "r1-eth1") == "", "fail-closed member re-attached"

    _register(r1, "fail-closed")
    _expect(_member_state, r1, "r1-eth1", ("mbfd-detached",), ("attached",), "")
    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 attach")
    _expect(_member_state, r1, "r1-eth1", ATTACHED_OK, ("mbfd-detached",), "bond0")


def test_state_saved_while_startup_read_pending():
    """
    A detach done while zebra still waits to act on its saved state (up to
    30 s after start when a saved interface is missing) is saved too, and
    the not-yet-handled saved lines are kept.
    """
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    _register(r1)
    _zebra_stop(tgen, r1, "TERM")
    # A line for an interface that doesn't exist keeps the startup read
    # retrying for ~30 s.
    # Owned by frr, like the file zebra writes itself (the run directory
    # may be sticky, so zebra couldn't replace a root-owned file).
    r1.run(
        "echo 'ghost0 bond0 1' > {0}; chown frr:frr {0} 2>/dev/null".format(STATE_FILE)
    )
    r1.run("ls -ld /var/run/frr {}".format(STATE_FILE))
    _zebra_start(tgen, r1)

    _register(r1)
    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 detach")
    _expect(_member_state, r1, "r1-eth1", ("mbfd-detached",), ("attached",), "")
    _expect(_state_has, r1, "r1-eth1 bond0 1")
    assert _state_has(r1, "ghost0 bond0 1") is None, "unhandled saved line lost"

    r1.vtysh_cmd("sharp lag-mbfd bond bond0 member r1-eth1 attach")
    _expect(_member_state, r1, "r1-eth1", ATTACHED_OK, ("mbfd-detached",), "bond0")
    # After the retries the missing interface's line is dropped.
    _expect(
        lambda: (
            None
            if _state_has(r1, "ghost0 bond0 1") is not None
            else "ghost0 line still saved"
        ),
        count=50,
        wait=1,
    )


def test_unsupported_mode_and_not_found():
    "An active-backup bond is unsupported; a deleted bond is not-found."
    tgen = get_topogen()
    _skip(tgen)
    r1 = tgen.gears["r1"]

    r1.run("ip link add bond9 type bond mode active-backup")
    r1.run("ip link set bond9 up")
    _expect(lambda: None if "bond9" in r1.vtysh_cmd("show interface brief") else "wait")

    r1.vtysh_cmd("sharp lag-mbfd bond bond9")
    _expect(_bond_status, r1, "bond9", "unsupported-mode")

    r1.run("ip link del bond9")
    _expect(
        lambda: (
            None
            if not _sharp(r1)["bonds"].get("bond9")
            or _sharp(r1)["bonds"]["bond9"]["status"] == "not-found"
            else "wait"
        )
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
