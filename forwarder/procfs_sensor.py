"""
Security-Core Event Forwarder — /proc Process Sensor

Live process discovery for platforms where eBPF is unavailable.

WHY THIS EXISTS
---------------
Tetragon publishes no ``linux/s390x`` build, and the Datathon-allocated
LinuxONE instance has no container runtime, so a Tetragon DaemonSet cannot be
deployed there. This module provides the alternative: an unprivileged poller
that reads the Linux process table directly.

WHAT THIS IS NOT
----------------
This is **not** eBPF and must never be reported as such. The differences are
material and are surfaced through the ``sensor_kind`` field and the UI badge:

* It observes process **state** on a poll interval, not kernel **events**.
  A process that starts and exits between two polls is never seen.
* It cannot observe ``connect()`` or any other syscall.
* It needs no privileges, no kernel module, and no tracing filesystem.

WHAT IT DOES GIVE
-----------------
Real, live process telemetry captured natively on the target architecture,
in the same unified schema as every other source, with the same redaction
applied before persistence. On IBM Z this is what turns the demo from
"fixtures replayed on s390x" into "live telemetry from IBM Z".

PRIVACY
-------
A live command-line sensor on a shared machine can capture credential-bearing
daemons. Two defaults narrow that:

1. Kernel threads (empty cmdline, parented to PID 2) are always skipped.
2. ``PROCFS_DENYLIST`` matches on ``/proc/PID/comm`` — the kernel-truncated
   process name — rather than the command line, so it cannot be evaded by
   padding argv. The shipped default excludes sshd, cron,
   unattended-upgrades, and systemd.

The sensor also never observes itself or its own ancestors, which would
otherwise produce a self-sustaining feedback loop.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Iterator

from .config import Config

logger = logging.getLogger("security.procfs")

PROC_ROOT = Path("/proc")

# Kernel threads have PPid 2 and an empty cmdline.
KTHREADD_PID = 2


class ProcfsSensor:
    """
    Polls /proc and yields raw event dicts shaped for ``transform_event()``.

    Emits ``process_exec`` for newly observed processes and for processes whose
    executable or command line changed (an exec-in-place). Optionally emits
    ``process_exit`` when a tracked PID disappears.
    """

    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self._denylist = {
            name.strip().lower()
            for name in self.config.PROCFS_DENYLIST.split(",")
            if name.strip()
        }
        self._interval = max(0.5, float(self.config.PROCFS_POLL_INTERVAL))
        self._emit_exits = self.config.PROCFS_EMIT_EXITS
        self._max_args = self.config.PROCFS_MAX_ARGS

        # pid -> fingerprint of (exe, cmdline, rss-bucket). Used to emit on
        # change rather than on every poll, which would otherwise flood Redis.
        self._seen: dict[int, str] = {}
        self._comm: dict[int, str] = {}

        self._self_pids = self._resolve_self_lineage()
        self._shutdown = threading.Event()
        self.last_scan_at: float | None = None
        self.last_error: str | None = None
        self.scans: int = 0

    # ── self-protection ──────────────────────────────────────────
    def _resolve_self_lineage(self) -> set[int]:
        """
        PIDs of this process and all its ancestors.

        Without this the sensor would observe its own ancestors (the shell, the
        SSH session driving it) and could feed itself.
        """
        lineage: set[int] = set()
        pid = os.getpid()
        # Bounded walk: a malformed or cyclic ppid chain must not hang startup.
        for _ in range(64):
            if pid <= 1:
                break
            if pid in lineage:
                break
            lineage.add(pid)
            try:
                stat = _read_stat(pid)
            except Exception:
                break
            # The parent may exit between getpid() and this read.
            if stat is None:
                break
            pid = stat.get("ppid", 0)
        return lineage

    def _is_self_or_ancestor(self, pid: int) -> bool:
        return pid in self._self_pids

    # ── filtering ───────────────────────────────────────────────
    def _is_excluded(self, pid: int, comm: str, cmdline: list[str], ppid: int) -> str | None:
        """Return a reason string when this process must not be observed."""
        if self._is_self_or_ancestor(pid):
            return "self-lineage"
        # kthreadd (PID 2) is always kernel-side and is never a useful signal.
        if pid == KTHREADD_PID:
            return "kernel-thread"
        # Kernel threads: no cmdline and parented to kthreadd (PID 2).
        if not cmdline and ppid == KTHREADD_PID:
            return "kernel-thread"
        # Bracketed names such as [kworker/0:1] are kernel threads.
        if comm and comm.startswith("[") and comm.endswith("]"):
            return "kernel-thread"
        if comm.lower() in self._denylist:
            return "denylist"
        return None

    # ── scanning ─────────────────────────────────────────────────
    def scan_once(self) -> list[dict[str, Any]]:
        """Take one reading of /proc and return raw events for changes."""
        raw_events: list[dict[str, Any]] = []
        now = time.time()
        seen_this_pass: set[int] = set()

        try:
            entries = sorted(
                int(p.name)
                for p in PROC_ROOT.iterdir()
                if p.name.isdigit()
            )
        except (OSError, PermissionError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("procfs scan aborted: %s", self.last_error)
            return raw_events

        for pid in entries:
            proc = self._read_process(pid)
            if proc is None:
                # Vanished mid-scan: normal, not an error.
                continue

            comm = proc["comm"]
            cmdline = proc["cmdline"]
            ppid = proc["ppid"]

            reason = self._is_excluded(pid, comm, cmdline, ppid)
            if reason:
                continue

            seen_this_pass.add(pid)
            self._comm[pid] = comm

            fingerprint = _fingerprint(proc)
            previous = self._seen.get(pid)

            if previous is None:
                raw_events.append(self._to_raw_event(proc, "process_exec", now))
            elif previous != fingerprint:
                # Same PID but new exe/argv => an exec-in-place.
                raw_events.append(self._to_raw_event(proc, "process_exec", now))

            self._seen[pid] = fingerprint

        # Exits: PIDs we tracked that are gone this pass.
        if self._emit_exits:
            for pid in set(self._seen) - seen_this_pass:
                if self._is_self_or_ancestor(pid):
                    continue
                raw_events.append(self._exit_event(pid, self._comm.get(pid, "unknown"), now))
                self._seen.pop(pid, None)
                self._comm.pop(pid, None)

        # Forget exited PIDs that we chose not to emit (denylist churn).
        for pid in set(self._seen) - seen_this_pass:
            self._seen.pop(pid, None)
            self._comm.pop(pid, None)

        self.scans += 1
        self.last_scan_at = now
        self.last_error = None
        return raw_events

    def _read_process(self, pid: int) -> dict[str, Any] | None:
        """Read one PID defensively; every field may be unreadable."""
        base = PROC_ROOT / str(pid)
        stat = _read_stat(pid)
        if stat is None:
            return None

        cmdline = _read_cmdline(base, self._max_args)
        status = _read_status(base)
        exe = _readlink(base / "exe")
        cwd = _readlink(base / "cwd")

        return {
            "pid": pid,
            "ppid": stat.get("ppid", 0),
            "comm": stat.get("comm", ""),
            "state": stat.get("state", ""),
            # UID comes from status only; /proc/PID/stat does not carry it.
            "uid": status.get("uid", 0),
            "rss_kb": status.get("vm_rss_kb", 0),
            "threads": status.get("threads", stat.get("num_threads", 0)),
            "cmdline": cmdline,
            "exe": exe,
            "cwd": cwd,
            "started_at": stat.get("starttime", 0),
        }

    # ── event shaping ────────────────────────────────────────────
    def _to_raw_event(self, proc: dict[str, Any], event_type: str, ts: float) -> dict[str, Any]:
        """Shape a /proc reading like a Tetragon record for transform_event()."""
        exe = proc["exe"] or (proc["cmdline"][0] if proc["cmdline"] else "")
        binary = exe or proc["comm"] or "unknown"

        # argv[0] is already the executable path; avoid duplicating it.
        argv = list(proc["cmdline"])
        if argv and exe and argv[0] == exe:
            args = argv[1:]
        else:
            args = argv

        return {
            "time": ts,
            "node_name": os.getenv("SOURCE_HOST", self.config.SOURCE_HOST),
            "process_exec" if event_type == "process_exec" else event_type: {
                "process": {
                    "pid": proc["pid"],
                    "uid": proc["uid"],
                    "binary": binary,
                    "arguments": args,
                    "cwd": proc["cwd"],
                    "docker": "",
                    "parent": {
                        "pid": proc["ppid"],
                        "binary": self._comm.get(proc["ppid"], ""),
                    },
                },
                "pod": {"name": "", "namespace": ""},
                # procfs-specific context, carried through untouched by the
                # transformer and useful for the live process view.
                "sensor": {
                    "comm": proc["comm"],
                    "state": proc["state"],
                    "threads": proc["threads"],
                    "rss_kb": proc["rss_kb"],
                    "exe": proc["exe"],
                    "observed_at": ts,
                },
            },
        }

    def _exit_event(self, pid: int, comm: str, ts: float) -> dict[str, Any]:
        """Minimal process_exit record. /proc is already gone, so this is a tombstone."""
        return {
            "time": ts,
            "node_name": os.getenv("SOURCE_HOST", self.config.SOURCE_HOST),
            "process_exit": {
                "process": {
                    "pid": pid,
                    "uid": 0,
                    "binary": comm or "unknown",
                    "arguments": "",
                    "cwd": "",
                    "docker": "",
                    "parent": {"pid": 0, "binary": ""},
                },
                "pod": {"name": "", "namespace": ""},
                "sensor": {"comm": comm, "state": "exited", "observed_at": ts},
            },
        }

    # ── lifecycle ────────────────────────────────────────────────
    def run(self) -> Iterator[dict[str, Any]]:
        """Yield raw events until shutdown. Blocking; run in a thread."""
        logger.info(
            "procfs sensor starting: interval=%.1fs denylist=%s excluded_self=%s",
            self._interval,
            sorted(self._denylist) or "(none)",
            sorted(self._self_pids),
        )
        while not self._shutdown.is_set():
            for raw in self.scan_once():
                yield raw
            self._shutdown.wait(self._interval)
        logger.info("procfs sensor stopped after %d scans", self.scans)

    def stop(self) -> None:
        self._shutdown.set()

    # ── introspection (used by /api/procs) ───────────────────────
    def snapshot(self) -> list[dict[str, Any]]:
        """Current process table, unfiltered by event dedup. Read-only."""
        rows: list[dict[str, Any]] = []
        try:
            entries = sorted(
                int(p.name) for p in PROC_ROOT.iterdir() if p.name.isdigit()
            )
        except (OSError, PermissionError):
            return rows

        for pid in entries:
            proc = self._read_process(pid)
            if proc is None:
                continue
            if self._is_excluded(
                pid, proc["comm"], proc["cmdline"], proc["ppid"]
            ):
                continue
            rows.append(
                {
                    "pid": proc["pid"],
                    "ppid": proc["ppid"],
                    "comm": proc["comm"],
                    "uid": proc["uid"],
                    "state": proc["state"],
                    "threads": proc["threads"],
                    "rss_kb": proc["rss_kb"],
                    "exe": proc["exe"],
                    "args": proc["cmdline"],
                }
            )
        return rows


# ── /proc parsing helpers ──────────────────────────────────────

def _read_stat(pid: int) -> dict[str, Any] | None:
    """
    Parse /proc/PID/stat.

    comm (field 2) is wrapped in parentheses and may itself contain spaces and
    parentheses, so parsing is anchored on the LAST ')' rather than a split.
    """
    try:
        text = (PROC_ROOT / str(pid) / "stat").read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError, ProcessLookupError):
        return None

    try:
        rparen = text.rindex(")")
        comm = text[text.index("(") + 1 : rparen]
        rest = text[rparen + 2 :].split()
        # rest[0] is state (field 3), so field N lives at rest[N-3].
        state = rest[0]
        ppid = int(rest[1])
        num_threads = int(rest[17])
        starttime = int(rest[19])
    except (ValueError, IndexError):
        return None

    # NOTE: /proc/PID/stat has no UID field. Field 24 is RSS, not UID —
    # reading it as one silently reports tpgid/rss garbage as identity.
    # UID is taken from /proc/PID/status instead.
    return {
        "comm": comm,
        "state": state,
        "ppid": ppid,
        "num_threads": num_threads,
        "starttime": starttime,
    }


def _read_cmdline(base: Path, limit: int) -> list[str]:
    """Read NUL-separated argv. Empty for kernel threads."""
    try:
        raw = (base / "cmdline").read_bytes()
    except (OSError, PermissionError):
        return []
    parts = [p for p in raw.split(b"\0") if p]
    return [p.decode("utf-8", errors="replace") for p in parts[:limit]]


def _read_status(base: Path) -> dict[str, Any]:
    """Parse the handful of /proc/PID/status fields we need."""
    out: dict[str, Any] = {}
    try:
        text = (base / "status").read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return out

    for line in text.splitlines():
        if line.startswith("Uid:"):
            try:
                out["uid"] = int(line.split()[1])
            except (ValueError, IndexError):
                pass
        elif line.startswith("VmRSS:"):
            try:
                out["vm_rss_kb"] = int(line.split()[1])
            except (ValueError, IndexError):
                pass
        elif line.startswith("Threads:"):
            try:
                out["threads"] = int(line.split()[1])
            except (ValueError, IndexError):
                pass
    return out


def _readlink(path: Path) -> str:
    """
    Resolve /proc/PID/exe or cwd.

    Succeeds only for processes the caller may inspect; returns "" otherwise.
    A non-empty exe is never asserted, so a blank is honest rather than a gap.
    """
    try:
        return os.readlink(path)
    except (OSError, PermissionError):
        return ""


def _fingerprint(proc: dict[str, Any]) -> str:
    """
    Cheap change detector: identity + argv + coarse RSS bucket.

    RSS is bucketed to 256 KiB so ordinary memory churn does not generate an
    exec event every poll, while a genuine step change still surfaces.
    """
    argv = "\x00".join(proc["cmdline"])
    rss_bucket = proc["rss_kb"] // 256
    return f"{proc['exe']}\x01{argv}\x01{rss_bucket}"