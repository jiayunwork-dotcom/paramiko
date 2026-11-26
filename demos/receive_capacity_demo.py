#!/usr/bin/env python3
"""
Terminal demonstration of Paramiko connection-wide receive capacity.

Both SSH Transport endpoints are connected through the in-process
``tests._loop.LoopSocket``; no real SSH server or network socket is used.

Run from a source checkout with::

    python3 demos/receive_capacity_demo.py
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from paramiko import (  # noqa: E402
    ChannelException,
    RSAKey,
    Transport,
)
from paramiko.common import (  # noqa: E402
    cMSG_CHANNEL_DATA,
    cMSG_CHANNEL_EXTENDED_DATA,
)
from paramiko.message import Message  # noqa: E402
from paramiko.receive_capacity import ChannelWindowOverflow  # noqa: E402
from tests._loop import LoopSocket  # noqa: E402
from tests._util import TestServer, _support  # noqa: E402

logging.basicConfig(level=logging.CRITICAL)
RSA_KEY = _support("rsa.key")
CHECKS = []


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"FAILED: {name} {detail}")
    CHECKS.append(name)
    print(f"  \033[32mPASS\033[0m {name}" + (f" — {detail}" if detail else ""))


def wait_until(predicate, timeout=8, label="condition"):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {label}")


def make_pair(client_budget=196608, server_budget=196608):
    sockc = LoopSocket()
    socks = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc, receive_capacity=client_budget)
    ts = Transport(socks, receive_capacity=server_budget)
    key = RSAKey.from_private_key_file(RSA_KEY)
    ts.add_server_key(key)
    ready = threading.Event()
    ts.start_server(ready, TestServer())
    tc.connect(
        hostkey=RSAKey(data=key.asbytes()),
        username="slowdive",
        password="pygmalion",
    )
    wait_until(ready.is_set, label="server ready")
    return tc, ts, sockc, socks


def open_pair(tc, ts):
    c = tc.open_session(timeout=5)
    s = ts.accept(5)
    if s is None:
        raise AssertionError("server did not accept channel")
    return c, s


def recv_exact(chan, size):
    chan.settimeout(15)
    out = []
    remain = size
    while remain:
        chunk = chan.recv(min(remain, 16384))
        if not chunk:
            raise AssertionError("channel closed early")
        out.append(chunk)
        remain -= len(chunk)
    return b"".join(out)


def send_packet(sender, target, payload, stderr=False):
    m = Message()
    if stderr:
        m.add_byte(cMSG_CHANNEL_EXTENDED_DATA)
        m.add_int(sender.remote_chanid)
        m.add_int(1)
    else:
        m.add_byte(cMSG_CHANNEL_DATA)
        m.add_int(sender.remote_chanid)
    m.add_string(payload)
    sender.transport._send_user_message(m)


def section(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def demo_validation():
    section("1. B validation and unset-B compatibility")
    Transport(LoopSocket(), receive_capacity=65536).close()
    check("B=65536 accepted", True)
    for value in (65535, 0, -1, 1.0, "65536", True):
        try:
            Transport(LoopSocket(), receive_capacity=value)
        except (ValueError, TypeError):
            pass
        else:
            raise AssertionError(f"invalid B accepted: {value!r}")
    check("small/non-integer B rejected", True)

    sock = LoopSocket()
    legacy = Transport(sock)
    try:
        check(
            "B=None preserves legacy 2 MiB default window",
            legacy._receive_capacity is None
            and legacy.default_window_size == 2 * 64 * 2**14,
        )
    finally:
        legacy.close()
        sock.close()


def demo_open_rejection():
    section("2. Local and remote new-channel rejection")
    tc, ts, sc, ss = make_pair(196608, 10 * 1024 * 1024)
    held = []
    try:
        for _ in range(3):
            held.append(open_pair(tc, ts))
        check(
            "three 64 KiB initial windows reserve B=196608",
            tc.receive_capacity_used == 196608,
            f"used={tc.receive_capacity_used}",
        )
        try:
            tc.open_session(timeout=2)
        except ChannelException as exc:
            check(
                "local fourth channel explicitly rejected",
                exc.code == 4,
                type(exc).__name__,
            )
        else:
            raise AssertionError("fourth local channel was admitted")
    finally:
        tc.close()
        ts.close()
        sc.close()
        ss.close()

    # Server B=65536 admits one default channel; next OPEN gets SSH failure.
    tc, ts, sc, ss = make_pair(None, 65536)
    try:
        first = open_pair(tc, ts)
        check("remote first channel admitted", first is not None)
        try:
            tc.open_session(timeout=5)
        except ChannelException as exc:
            check(
                "remote second channel rejected with OPEN_FAILURE code 4",
                exc.code == 4,
            )
        else:
            raise AssertionError("second remote channel was admitted")
        assert first is not None
    finally:
        tc.close()
        ts.close()
        sc.close()
        ss.close()


def demo_accounting_and_progress():
    section("3/4/7. Buffers, stdout/stderr, fairness, and progress")
    B = 196608
    tc, ts, sc, ss = make_pair(B, B)
    errors = []
    stop = threading.Event()
    try:
        slow_c, slow_s = open_pair(tc, ts)
        fast_c, fast_s = open_pair(tc, ts)

        # Exact stdout/stderr/combined accounting on a third short-lived pair.
        ac, ass = open_pair(tc, ts)
        ass.sendall(b"out" * 100)
        ass.send_stderr(b"err" * 100)
        wait_until(
            lambda: len(ac.in_buffer) == 300
            and len(ac.in_stderr_buffer) == 300,
            label="stdout/stderr arrival",
        )
        check(
            "stdout+stderr still fit the initial 64 KiB window",
            ac.receive_occupancy() == 65536,
            f"occupancy={ac.receive_occupancy()}",
        )
        assert recv_exact(ac, 300) == b"out" * 100
        err = b""
        ac.settimeout(5)
        while len(err) < 300:
            chunk = ac.recv_stderr(300 - len(err))
            if not chunk:
                break
            err += chunk
        check("recv and recv_stderr return exact bytes", err == b"err" * 100)

        ass.send_stderr(b"mix" * 100)
        wait_until(lambda: len(ac.in_stderr_buffer) == 300)
        ac.set_combine_stderr(True)
        mixed = recv_exact(ac, 300)
        check(
            "combined stderr is read once without double refund",
            mixed == b"mix" * 100
            and tc._receive_capacity.snapshot()["channels"][ac.chanid][
                "buffered"
            ]
            == 0,
        )
        ac.close()
        ass.close()

        slow_payload = b"S" * 65536
        fast_payload = b"F" * (512 * 1024)

        def writer(chan, data):
            try:
                chan.sendall(data)
            except Exception as exc:
                errors.append(exc)

        threading.Thread(
            target=writer, args=(slow_s, slow_payload), daemon=True
        ).start()
        wait_until(
            lambda: len(slow_c.in_buffer) == 65536, label="slow channel fill"
        )
        threading.Thread(
            target=writer, args=(fast_s, fast_payload), daemon=True
        ).start()

        max_seen = 0

        def sampler():
            nonlocal max_seen
            while not stop.is_set():
                used = tc.receive_capacity_used
                max_seen = max(max_seen, used)
                if used > B:
                    errors.append(AssertionError(f"B exceeded: {used}"))
                time.sleep(0.002)

        t = threading.Thread(target=sampler, daemon=True)
        t.start()
        got = recv_exact(fast_c, len(fast_payload))
        stop.set()
        t.join(2)
        check(
            "continuously read channel transfers 512 KiB while peer stopped",
            got == fast_payload and not errors,
            f"max connection occupancy={max_seen}/{B}",
        )
        check(
            "stopped channel's unread cache stayed intact",
            len(slow_c.in_buffer) == 65536,
        )
        check(
            "sampled connection occupancy never exceeded B", max_seen <= B
        )
    finally:
        stop.set()
        tc.close()
        ts.close()
        sc.close()
        ss.close()
        if errors:
            raise errors[0]


def demo_concurrent_opens():
    section("2 (concurrency). Parallel opens, packets, and reads stay <= B")
    B = 524288
    tc, ts, sc, ss = make_pair(B, B)
    n = 4
    clients = [None] * n
    errors = []
    barrier = threading.Barrier(n)
    stop_sampler = threading.Event()

    def open_one(index):
        try:
            barrier.wait()
            clients[index] = tc.open_session(timeout=10)
        except Exception as exc:
            errors.append(exc)

    try:
        threads = [
            threading.Thread(target=open_one, args=(i,), daemon=True)
            for i in range(n)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        check(
            "four parallel opens all succeed",
            not errors and all(c is not None for c in clients),
            str(errors[:1]),
        )

        by_remote = {}
        for _ in range(n):
            s = ts.accept(10)
            by_remote[s.remote_chanid] = s
        pairs = [(c, by_remote[c.chanid]) for c in clients]
        check(
            "parallel reservations sum exactly to B",
            tc.receive_capacity_used == B,
            f"used={tc.receive_capacity_used}",
        )

        payload = b"C" * (96 * 1024)

        def transfer(c, s):
            try:
                wt = threading.Thread(
                    target=s.sendall, args=(payload,), daemon=True
                )
                wt.start()
                got = recv_exact(c, len(payload))
                wt.join(10)
                if got != payload or wt.is_alive():
                    errors.append(AssertionError("transfer mismatch"))
            except Exception as exc:
                errors.append(exc)

        workers = [
            threading.Thread(target=transfer, args=p, daemon=True)
            for p in pairs
        ]

        def sample():
            while not stop_sampler.is_set():
                if tc.receive_capacity_used > B:
                    errors.append(AssertionError("B exceeded"))
                    return
                time.sleep(0.001)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        for w in workers:
            w.start()
        for w in workers:
            w.join(30)
        stop_sampler.set()
        sampler.join(2)
        check(
            "parallel send/receive/read transfers preserve bound and bytes",
            not errors and all(not w.is_alive() for w in workers),
            str(errors[:1]),
        )
        tc.verify_receive_capacity()
    finally:
        stop_sampler.set()
        tc.close()
        ts.close()
        sc.close()
        ss.close()
        if errors:
            raise errors[0]


def demo_lifecycle_and_overflow():
    section("5/6. EOF/close/disconnect and over-window protocol error")
    tc, ts, sc, ss = make_pair(65536, 65536)
    try:
        c, s = open_pair(tc, ts)
        s.sendall(b"lifecycle" * 1000)
        wait_until(lambda: len(c.in_buffer) == 9000)
        s.close()
        wait_until(lambda: c.eof_received or c.closed, label="EOF")
        snap = tc._receive_capacity.snapshot()["channels"][c.chanid]
        check(
            "EOF reclaims window but keeps 9000 unread bytes charged",
            snap["window"] == 0 and snap["buffered"] == 9000,
        )
        c.close()
        c.close()
        check(
            "repeated close does not release unread cache twice",
            tc.receive_capacity_used == 9000,
        )
        data = recv_exact(c, 9000)
        wait_until(
            lambda: tc.receive_capacity_used == 0,
            label="account deletion after read",
        )
        check(
            "reading all cached bytes leaves zero occupancy",
            data == b"lifecycle" * 1000
            and tc.receive_capacity_used == 0,
        )
        tc.close()
        ts.close()
    finally:
        sc.close()
        ss.close()

    tc, ts, sc, ss = make_pair(65536, 65536)
    try:
        c, s = open_pair(tc, ts)
        s.sendall(b"disconnect" * 800)  # 8000 bytes
        wait_until(lambda: len(c.in_buffer) == 8000)
        tc.close()
        wait_until(lambda: not tc.is_active(), label="transport close")
        check(
            "connection disconnect revokes window but preserves cache",
            tc.receive_capacity_used == 8000
            and tc._receive_capacity.snapshot()["channels"][c.chanid][
                "window"
            ]
            == 0,
        )
        data = recv_exact(c, 8000)
        check(
            "disconnected cache releases capacity only after read",
            data == b"disconnect" * 800
            and tc.receive_capacity_used == 0,
        )
    finally:
        tc.close()
        ts.close()
        sc.close()
        ss.close()

    tc, ts, sc, ss = make_pair(65536, 65536)
    try:
        c, s = open_pair(tc, ts)
        window = c.in_window_remaining
        send_packet(s, c, b"X" * (window + 32))
        wait_until(lambda: not tc.is_active(), timeout=8, label="disconnect")
        exc = tc.saved_exception
        check(
            "over-window DATA rejected before BufferedPipe growth",
            isinstance(exc, ChannelWindowOverflow)
            and len(c.in_buffer) == 0,
            type(exc).__name__,
        )
    finally:
        tc.close()
        ts.close()
        sc.close()
        ss.close()


def main():
    demo_validation()
    demo_open_rejection()
    demo_concurrent_opens()
    demo_accounting_and_progress()
    demo_lifecycle_and_overflow()
    print("\n" + "#" * 78)
    print(
        f"DEMO PASSED: {len(CHECKS)} terminal checks covered all "
        "requested areas"
    )
    print("#" * 78)


if __name__ == "__main__":
    main()
