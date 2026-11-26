# Copyright (C) 2026 Paramiko contributors
# Licensed under the GNU Lesser General Public License, version 2.1 or later.

"""
Tests for Transport-wide shared receive capacity.

These tests use :class:`tests._loop.LoopSocket`, so both SSH endpoints live in
this process and no real socket or SSH server is required.
"""

from __future__ import annotations

import threading
import time

import pytest

import paramiko
from paramiko.buffered_pipe import BufferedPipe
from paramiko.common import (
    cMSG_CHANNEL_DATA,
    cMSG_CHANNEL_EXTENDED_DATA,
)
from paramiko.message import Message
from paramiko.receive_capacity import (
    ChannelWindowOverflow,
    MIN_RECEIVE_CAPACITY,
    ReceiveCapacity,
    ReceiveCapacityError,
)
from paramiko.ssh_exception import ChannelException

from ._loop import LoopSocket
from ._util import TestServer, _support


RSA_KEY = _support("rsa.key")
PASSWORD = "pygmalion"
USERNAME = "slowdive"


def wait_until(predicate, timeout=8.0, interval=0.01, message=None):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:  # keep polling until timeout
            last = exc
        time.sleep(interval)
    raise AssertionError(
        message or f"condition was not met within {timeout}s"
    ) from last


class CapacityPair:
    def __init__(self, client_budget=131072, server_budget=131072):
        self.client_sock = LoopSocket()
        self.server_sock = LoopSocket()
        self.client_sock.link(self.server_sock)
        self.client = paramiko.Transport(
            self.client_sock, receive_capacity=client_budget
        )
        self.server = paramiko.Transport(
            self.server_sock, receive_capacity=server_budget
        )
        host_key = paramiko.RSAKey.from_private_key_file(RSA_KEY)
        self.server.add_server_key(host_key)
        self.ready = threading.Event()
        self.server.start_server(self.ready, TestServer())
        public_key = paramiko.RSAKey(data=host_key.asbytes())
        self.client.connect(
            hostkey=public_key, username=USERNAME, password=PASSWORD
        )
        if not self.ready.wait(5):
            raise AssertionError("test server did not become ready")

    def open_channel_pair(self, timeout=5):
        client_chan = self.client.open_session(timeout=timeout)
        server_chan = self.server.accept(timeout)
        if server_chan is None:
            raise AssertionError("server did not accept channel")
        return client_chan, server_chan

    def close(self):
        for transport in (self.client, self.server):
            try:
                transport.close()
            except Exception:
                pass
        for sock in (self.client_sock, self.server_sock):
            try:
                sock.close()
            except Exception:
                pass


@pytest.fixture
def pair():
    environment = CapacityPair()
    try:
        yield environment
    finally:
        environment.close()


def send_window_packet(sender, recipient_chan, payload, extended=False):
    """Inject DATA/EXTENDED_DATA while bypassing send-window checks."""
    message = Message()
    if extended:
        message.add_byte(cMSG_CHANNEL_EXTENDED_DATA)
        message.add_int(sender.remote_chanid)
        message.add_int(1)  # SSH_EXTENDED_DATA_STDERR
    else:
        message.add_byte(cMSG_CHANNEL_DATA)
        message.add_int(sender.remote_chanid)
    message.add_string(payload)
    sender.transport._send_user_message(message)


def receive_exactly(chan, size, timeout=10):
    chan.settimeout(timeout)
    chunks = []
    remaining = size
    while remaining:
        chunk = chan.recv(min(remaining, 16384))
        if not chunk:
            raise AssertionError(
                f"channel closed with {remaining} bytes still expected"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# 1. Construction and rejection of new channels
# ---------------------------------------------------------------------------


def test_capacity_must_be_int_at_or_above_minimum():
    assert ReceiveCapacity(MIN_RECEIVE_CAPACITY).limit == 65536
    sock = LoopSocket()
    transport = paramiko.Transport(sock, receive_capacity=131072)
    try:
        assert transport.receive_capacity == 131072
        assert isinstance(transport._receive_capacity, ReceiveCapacity)
        assert transport.receive_capacity_used == 0
    finally:
        transport.close()
        sock.close()

    for invalid in (65535, 0, -1024, 1.5 * 1024 * 1024, "65536", True):
        with pytest.raises((ValueError, TypeError)):
            paramiko.Transport(LoopSocket(), receive_capacity=invalid)

    # A descriptive compatibility keyword is accepted as the same B.
    sock2 = LoopSocket()
    aliased = paramiko.Transport(
        sock2, max_receive_buffer_size=65536
    )
    try:
        assert aliased.receive_capacity == 65536
    finally:
        aliased.close()
        sock2.close()


def test_unconfigured_transport_keeps_legacy_window(pair):
    # The fixture configures both ends; make a separate default Transport pair.
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    client = paramiko.Transport(sockc)
    server = paramiko.Transport(socks)
    host_key = paramiko.RSAKey.from_private_key_file(RSA_KEY)
    server.add_server_key(host_key)
    event = threading.Event()
    server.start_server(event, TestServer())
    client.connect(
        hostkey=paramiko.RSAKey(data=host_key.asbytes()),
        username=USERNAME,
        password=PASSWORD,
    )
    try:
        assert event.wait(5)
        chan = client.open_session(timeout=5)
        schan = server.accept(5)
        assert chan._shared_capacity() is None
        assert chan.in_window_size == paramiko.common.DEFAULT_WINDOW_SIZE
        assert chan.in_window_threshold == chan.in_window_size // 10
        before = chan.in_window_sofar
        assert chan._check_add_window(1) == 0
        assert chan.in_window_sofar == before + 1
        chan.close()
        schan.close()
    finally:
        client.close()
        server.close()
        socks.close()
        sockc.close()


def test_local_channel_is_rejected_when_shared_budget_is_full():
    env = CapacityPair(client_budget=131072, server_budget=10 * 1024 * 1024)
    try:
        c1, _ = env.open_channel_pair()
        c2, _ = env.open_channel_pair()
        assert c1.in_window_size == 65536
        assert c2.in_window_size == 65536
        assert env.client.receive_capacity_used == 131072

        with pytest.raises(ReceiveCapacityError) as exc_info:
            env.client.open_session(timeout=2)
        assert exc_info.value.code == 4
        assert env.client.receive_capacity_used == 131072
        env.client.verify_receive_capacity()
    finally:
        env.close()


def test_remote_requested_channel_is_rejected_with_ssh_failure():
    # Server B admits only two 64 KiB default channels; client is
    # unrestricted so the third OPEN reaches the server and receives an
    # OPEN_FAILURE resource-shortage reply.
    env = CapacityPair(client_budget=None, server_budget=131072)
    try:
        first = env.open_channel_pair()
        second = env.open_channel_pair()
        assert first and second
        with pytest.raises(ChannelException) as exc_info:
            env.client.open_session(timeout=5)
        assert exc_info.value.code == 4
        wait_until(
            lambda: env.server._receive_capacity.occupied == 131072,
            message="server capacity should retain two windows",
        )
    finally:
        env.close()


def test_failed_remote_open_releases_local_reservation():
    # Client can admit three channels, server only two.  The third is reserved
    # locally, then released when OPEN_FAILURE arrives.
    env = CapacityPair(client_budget=196608, server_budget=131072)
    try:
        first = env.open_channel_pair()
        second = env.open_channel_pair()
        assert first and second
        assert env.client.receive_capacity_used == 131072
        with pytest.raises(ChannelException) as exc_info:
            env.client.open_session(timeout=5)
        assert exc_info.value.code == 4

        wait_until(
            lambda: env.client.receive_capacity_used == 131072
            and len(env.client._receive_capacity.snapshot()["channels"]) == 2,
            message="failed open reservation was not released",
        )
    finally:
        env.close()


# ---------------------------------------------------------------------------
# 2/3. Payload bound and accounting consistency for stdout/stderr/combined
# ---------------------------------------------------------------------------


def test_explicit_window_request_is_honored_when_it_fits(pair):
    client_chan = pair.client.open_session(
        window_size=49152, timeout=5
    )
    server_chan = pair.server.accept(5)
    try:
        assert server_chan is not None
        assert client_chan.in_window_size == 49152
        assert client_chan.in_window_remaining == 49152
        assert pair.client.receive_capacity_used == 49152
    finally:
        client_chan.close()
        if server_chan is not None:
            server_chan.close()


def test_payload_converts_window_to_buffer_without_changing_occupancy(pair):
    chan, schan = pair.open_channel_pair()
    payload = b"A" * 65536
    schan.sendall(payload)

    wait_until(
        lambda: len(chan.in_buffer) == len(payload),
        message="payload did not arrive",
    )
    snapshot = pair.client.verify_receive_capacity()
    account = snapshot["channels"][chan.chanid]
    assert account["window"] == 0
    assert account["buffered"] == 65536
    assert account["occupied"] == 65536
    assert snapshot["occupied"] == 65536 == pair.client.receive_capacity_used
    assert chan.receive_occupancy() == 65536

    received = receive_exactly(chan, 65536)
    assert received == payload
    wait_until(
        lambda: chan.in_window_remaining > 0,
        message="read did not replenish window",
    )
    pair.client.verify_receive_capacity()


def test_stdout_and_stderr_reads_account_once(pair):
    chan, schan = pair.open_channel_pair()
    schan.sendall(b"out" * 2500)  # 7500
    schan.send_stderr(b"err" * 2000)  # 6000

    wait_until(
        lambda: len(chan.in_buffer) == 7500
        and len(chan.in_stderr_buffer) == 6000,
        message="stdout/stderr payloads did not arrive",
    )
    assert chan.receive_occupancy() == 65536

    out = receive_exactly(chan, 7500)
    err = b""
    chan.settimeout(10)
    while len(err) < 6000:
        chunk = chan.recv_stderr(6000 - len(err))
        assert chunk
        err += chunk
    assert out == b"out" * 2500
    assert err == b"err" * 2000

    wait_until(
        lambda: len(chan.in_buffer) == 0
        and len(chan.in_stderr_buffer) == 0,
        message="pipes were not drained",
    )
    pair.client.verify_receive_capacity()
    # The first 7500-byte read crosses the 6553-byte threshold and is
    # announced; the remaining 6000 stays as earmarked pending adjustment
    # until enough future reads accumulate.  Window + pending restores grant.
    account = pair.client._receive_capacity.snapshot()["channels"][chan.chanid]
    assert chan.in_window_remaining == 59536
    assert account["pending_adjust"] == 6000
    assert (
        chan.in_window_remaining + account["pending_adjust"] == 65536
    )


def test_combined_stderr_move_and_read_does_not_double_count(pair):
    chan, schan = pair.open_channel_pair()
    schan.send_stderr(b"combined" * 1000)  # 8000
    wait_until(
        lambda: len(chan.in_stderr_buffer) == 8000,
        message="stderr did not arrive",
    )

    old = chan.set_combine_stderr(True)
    assert old is False
    assert len(chan.in_stderr_buffer) == 0
    assert len(chan.in_buffer) == 8000
    snapshot = pair.client.verify_receive_capacity()
    assert snapshot["channels"][chan.chanid]["buffered"] == 8000

    data = receive_exactly(chan, 8000)
    assert data == b"combined" * 1000
    wait_until(
        lambda: len(chan.in_buffer) == 0,
        message="combined buffer was not read",
    )
    pair.client.verify_receive_capacity()
    # Reading through recv() after combining must be the only capacity refund.
    account = pair.client._receive_capacity.snapshot()["channels"][chan.chanid]
    assert account["buffered"] == 0
    assert account["pending_adjust"] >= 8000 or account["window"] > 0


def test_buffered_pipe_callback_cannot_double_release_on_merge():
    releases = []
    pipe = BufferedPipe(on_read=releases.append)
    pipe.feed(b"abcdef")
    assert pipe.read(3) == b"abc"
    assert releases == [3]
    # The merge path explicitly suppresses notification because bytes move to
    # the combined stdout pipe rather than being consumed by the application.
    assert pipe.empty(notify=False) == b"def"
    assert releases == [3]

    other = BufferedPipe(on_read=releases.append)
    other.feed(b"xyz")
    # A normal empty() drain is a read and does notify capacity accounting.
    assert other.empty() == b"xyz"
    assert releases == [3, 3]
    other.close()
    assert other.read(10, timeout=0) == b""


# ---------------------------------------------------------------------------
# 4/7. Progress, fairness, and dispatch non-blocking behavior
# ---------------------------------------------------------------------------


def test_stopped_channel_does_not_block_reading_channel():
    env = CapacityPair(client_budget=196608, server_budget=196608)
    sampler_errors = []
    stop_sampler = threading.Event()
    try:
        slow_c, slow_s = env.open_channel_pair()
        fast_c, fast_s = env.open_channel_pair()

        slow_payload = b"S" * 65536
        fast_payload = b"F" * (512 * 1024)

        def write_all(chan, payload):
            try:
                chan.sendall(payload)
            except Exception as exc:
                sampler_errors.append(exc)

        slow_writer = threading.Thread(
            target=write_all, args=(slow_s, slow_payload), daemon=True
        )
        fast_writer = threading.Thread(
            target=write_all, args=(fast_s, fast_payload), daemon=True
        )
        slow_writer.start()
        wait_until(
            lambda: len(slow_c.in_buffer) == 65536,
            message="slow channel should fill its initial window",
        )
        fast_writer.start()

        def sample():
            while not stop_sampler.is_set():
                try:
                    used = env.client.receive_capacity_used
                    assert 0 <= used <= env.client.receive_capacity
                    assert slow_c.receive_occupancy() <= 65536
                    assert fast_c.receive_occupancy() <= 65536
                    env.client._receive_capacity.verify()
                except Exception as exc:
                    sampler_errors.append(exc)
                    return
                time.sleep(0.002)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()

        received = receive_exactly(fast_c, len(fast_payload), timeout=20)
        stop_sampler.set()
        sampler.join(2)
        fast_writer.join(10)
        slow_writer.join(2)

        assert received == fast_payload
        assert not fast_writer.is_alive()
        assert not sampler_errors, sampler_errors[:3]
        # The stopped channel kept its unread payload throughout.
        assert len(slow_c.in_buffer) == 65536
        assert slow_c.receive_occupancy() == 65536
        assert not slow_writer.is_alive()
    finally:
        stop_sampler.set()
        env.close()


def test_concurrent_channels_all_progress_under_shared_budget():
    channel_count = 4
    budget = 524288  # four default 128 KiB quanta
    env = CapacityPair(client_budget=budget, server_budget=budget)
    errors = []
    stop_sampler = threading.Event()
    client_channels = [None] * channel_count

    def open_one(index):
        try:
            client_channels[index] = env.client.open_session(timeout=10)
        except Exception as exc:
            errors.append(exc)

    try:
        threads = [
            threading.Thread(target=open_one, args=(i,), daemon=True)
            for i in range(channel_count)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert not errors
        assert all(chan is not None for chan in client_channels)

        # Concurrent open_session() calls do not establish which worker
        # calls accept(); pair by SSH recipient ids rather than accept order.
        server_by_remote_id = {}
        for _ in range(channel_count):
            server_chan = env.server.accept(10)
            assert server_chan is not None
            server_by_remote_id[server_chan.remote_chanid] = server_chan
        channels = []
        for client_chan in client_channels:
            server_chan = server_by_remote_id[client_chan.chanid]
            channels.append((client_chan, server_chan))

        payload_size = 128 * 1024

        def transfer(client_chan, server_chan, index):
            try:
                payload = bytes((index % 251 + 1,)) * payload_size
                writer = threading.Thread(
                    target=server_chan.sendall,
                    args=(payload,),
                    daemon=True,
                )
                writer.start()
                received = receive_exactly(
                    client_chan, payload_size, timeout=25
                )
                writer.join(15)
                assert received == payload
                assert not writer.is_alive()
            except Exception as exc:
                errors.append(exc)

        transfer_threads = [
            threading.Thread(
                target=transfer, args=(c, s, i), daemon=True
            )
            for i, (c, s) in enumerate(channels)
        ]

        def sample():
            iteration = 0
            while not stop_sampler.is_set():
                try:
                    assert env.client.receive_capacity_used <= budget
                    for c, _ in channels:
                        occupancy = c.receive_occupancy()
                        assert 0 <= occupancy <= budget
                    iteration += 1
                    if iteration % 5 == 0:
                        # Coherent global audit exercises all pipe/capacity
                        # lock ordering while transfers are active.
                        env.client.verify_receive_capacity()
                except Exception as exc:
                    errors.append(exc)
                    return
                time.sleep(0.001)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        for t in transfer_threads:
            t.start()
        for t in transfer_threads:
            t.join(40)
        stop_sampler.set()
        sampler.join(2)

        assert not errors, errors[:5]
        for t in transfer_threads:
            assert not t.is_alive()
        wait_until(
            lambda: all(
                len(c.in_buffer) == 0 and len(c.in_stderr_buffer) == 0
                for c, _ in channels
            ),
            message="all channel pipes should be drained",
        )
        env.client.verify_receive_capacity()
    finally:
        stop_sampler.set()
        env.close()


# ---------------------------------------------------------------------------
# 5. EOF/close/disconnect reclamation
# ---------------------------------------------------------------------------


def test_eof_and_close_release_window_but_unread_bytes_remain(pair):
    chan, schan = pair.open_channel_pair()
    schan.sendall(b"keep-me" * 1000)  # 7000
    wait_until(lambda: len(chan.in_buffer) == 7000)

    schan.close()
    wait_until(lambda: chan.eof_received or chan.closed)

    def only_unread_left():
        snap = pair.client._receive_capacity.snapshot()
        account = snap["channels"].get(chan.chanid)
        return (
            account is not None
            and account["window"] == 0
            and account["buffered"] == 7000
            and snap["occupied"] == 7000
            and snap["allocated"] == 7000
        )

    wait_until(only_unread_left, message="EOF did not reclaim window")

    # Repeated local close must not release the same unread bytes twice.
    chan.close()
    chan.close()
    time.sleep(0.05)
    snap = pair.client._receive_capacity.snapshot()
    assert snap["occupied"] == 7000
    assert snap["channels"][chan.chanid]["buffered"] == 7000

    data = receive_exactly(chan, 7000)
    assert data == b"keep-me" * 1000
    wait_until(
        lambda: chan.chanid
        not in pair.client._receive_capacity.snapshot()["channels"],
        message="account remained after buffered data was read",
    )
    assert pair.client.receive_capacity_used == 0


def test_transport_disconnect_revokes_window_and_read_still_drains():
    env = CapacityPair(client_budget=65536, server_budget=65536)
    try:
        chan, schan = env.open_channel_pair()
        schan.sendall(b"disconnect-bytes" * 500)  # 8000
        wait_until(lambda: len(chan.in_buffer) == 8000)

        env.client.close()
        wait_until(lambda: not env.client.is_active())
        snap = env.client._receive_capacity.snapshot()
        assert snap["occupied"] == 8000
        assert snap["allocated"] == 8000
        assert snap["channels"][chan.chanid]["window"] == 0

        data = receive_exactly(chan, 8000, timeout=5)
        assert data == b"disconnect-bytes" * 500
        wait_until(
            lambda: env.client.receive_capacity_used == 0,
            message="disconnected channel leaked capacity after read",
        )
    finally:
        env.close()


# ---------------------------------------------------------------------------
# 6. Window violations are rejected before buffering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("extended", [False, True])
def test_peer_over_window_packet_is_protocol_error_before_buffer(
    pair, extended
):
    chan, schan = pair.open_channel_pair()
    window = chan.in_window_remaining
    assert window > 0
    send_window_packet(schan, chan, b"X" * (window + 16), extended=extended)

    wait_until(
        lambda: not pair.client.is_active(),
        timeout=8,
        message="over-window packet did not close client transport",
    )
    assert len(chan.in_buffer) == 0
    assert len(chan.in_stderr_buffer) == 0
    exc = pair.client.saved_exception
    assert isinstance(exc, ChannelWindowOverflow)
    assert exc.length == window + 16
    # The failed admit must not have consumed any window credit.
    assert chan.in_window_remaining == window


def test_dispatch_thread_does_not_wait_for_capacity(pair):
    # Filling one slow channel's window must not block dispatch of a small
    # packet to another channel.  The second channel still has its own window.
    slow_c, slow_s = pair.open_channel_pair()
    fast_c, fast_s = pair.open_channel_pair()

    slow_s.sendall(b"Z" * 65536)
    wait_until(lambda: len(slow_c.in_buffer) == 65536)
    # If dispatch were blocked waiting for free shared capacity, this would not
    # be fed even though the fast channel has 64 KiB of its own window.
    fast_s.sendall(b"ping")
    assert receive_exactly(fast_c, 4, timeout=5) == b"ping"
    assert len(slow_c.in_buffer) == 65536
