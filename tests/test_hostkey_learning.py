# Copyright (C) 2026  Paramiko contributors
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation; either version 2.1 of the License, or (at your
# option) any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Tests for OpenSSH-style host key learning (the ``hostkeys-00@openssh.com``
announcement and ``hostkeys-prove-00@openssh.com`` proof extensions, i.e.
the protocol behind OpenSSH's ``UpdateHostKeys``), which lets a client
learn a server's *new* host key over a connection still anchored in the
*old* one.
"""

import os
import threading
import time
from contextlib import contextmanager

import pytest

from paramiko import (
    AUTH_FAILED,
    AUTH_SUCCESSFUL,
    AutoAddPolicy,
    ECDSAKey,
    Ed25519Key,
    HostKeys,
    Message,
    RSAKey,
    ServerInterface,
    SSHClient,
    SSHException,
    Transport,
)
from paramiko.hostkeys import update_known_hosts_file
from paramiko.ssh_exception import BadHostKeyException, HostKeyProofError

from ._loop import LoopSocket
from ._util import _support


# ---------------------------------------------------------------------
# Fixture keys (all reused from the repository's existing test keys)
# ---------------------------------------------------------------------


def _demo_key(name):
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "..", "demos", name)


# The server's current ("old") host key, and the "new" keys it rotates to.
# NEW_RSA deliberately uses the *same algorithm* as OLD: during the
# overlap period both must be accepted for the same host.
OLD = RSAKey.from_private_key_file(_support("rsa.key"))
NEW_RSA = RSAKey.from_private_key_file(_demo_key("user_rsa_key"))
NEW_ECDSA = ECDSAKey.from_private_key_file(_support("ecdsa-256.key"))
NEW_ED = Ed25519Key.from_private_key_file(_support("ed25519.key"))

ALL_SERVER_KEYS = [OLD, NEW_RSA, NEW_ECDSA, NEW_ED]
NEW_KEYS = [NEW_RSA, NEW_ECDSA, NEW_ED]

HOST = "rotation.example.com"
PORT = 2222
# known_hosts name for the server, including the non-default port
NAME = "[{}]:{}".format(HOST, PORT)
PASSWORD = "pygmalion"


def plain_line(name, key):
    return "{} {} {}\n".format(name, key.get_name(), key.get_base64())


def hashed_line(name, key):
    return "{} {} {}\n".format(
        HostKeys.hash_host(name), key.get_name(), key.get_base64()
    )


# ---------------------------------------------------------------------
# Test server speaking the hostkeys announcement / proof extensions
# ---------------------------------------------------------------------


class RotatingServer(ServerInterface):
    """
    A minimal OpenSSH-like server: announces its host keys once user
    authentication completes, and answers ``hostkeys-prove`` requests
    with signatures bound to the connection's session ID.

    Knobs exist to produce broken proofs on purpose:

    - ``drop``: omit this many signatures from the response
    - ``extra``: append this many duplicate signatures to the response
    - ``tamper``: sign data that does not match the proof transcript
    - ``replay``: return these canned signatures verbatim
    - ``refuse``: deny the proof request outright
    - ``announce_extra``: public keys to announce but not prove
    """

    def __init__(
        self,
        private_keys,
        announce=True,
        drop=0,
        extra=0,
        tamper=False,
        replay=None,
        refuse=False,
        announce_extra=(),
    ):
        self.private_keys = {k.asbytes(): k for k in private_keys}
        self.announce = announce
        self.drop = drop
        self.extra = extra
        self.tamper = tamper
        self.replay = replay
        self.refuse = refuse
        self.announce_extra = list(announce_extra)
        self.recorded_signatures = []
        self.transport = None

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        if password == PASSWORD:
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def announce_when_authenticated(self, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.transport is not None and (
                self.transport.is_authenticated()
            ):
                break
            time.sleep(0.01)
        else:
            return
        keys = list(self.private_keys.values()) + self.announce_extra
        blobs = tuple(k.asbytes() for k in keys)
        self.transport.global_request(
            "hostkeys-00@openssh.com", blobs, wait=False
        )

    def check_global_request(self, kind, msg):
        if kind != "hostkeys-prove-00@openssh.com":
            return False
        if self.refuse:
            return False
        if self.replay is not None:
            return tuple(self.replay)
        blobs = []
        while len(msg.get_remainder()) > 0:
            blobs.append(msg.get_string())
        sigs = []
        for blob in blobs:
            key = self.private_keys.get(blob)
            if key is None:
                # Asked to prove a key we do not hold.
                return False
            proof = Message()
            proof.add_string("hostkeys-prove-00@openssh.com")
            proof.add_string(self.transport.session_id)
            proof.add_string(blob)
            if self.tamper:
                proof.add_string(b"not part of the real transcript")
            sigs.append(bytes(key.sign_ssh_data(bytes(proof))))
        self.recorded_signatures.extend(sigs)
        if self.drop:
            sigs = sigs[: -self.drop]
        for _ in range(self.extra):
            sigs.append(sigs[-1])
        return tuple(sigs)


@contextmanager
def rotation_server(prove_keys, handshake_keys=(OLD,), **server_knobs):
    """
    Run a `RotatingServer` on one end of a `LoopSocket` pair.

    ``handshake_keys`` are the transport's live host keys (one per
    algorithm, defaulting to the old key); ``prove_keys`` are the keys
    the server announces and can prove possession of.  Yields
    ``(server_transport, server, client_socket)``; the caller connects
    its client over ``client_socket``.
    """
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    ts = Transport(socks)
    for key in handshake_keys:
        ts.add_server_key(key)
    server = RotatingServer(prove_keys, **server_knobs)
    server.transport = ts
    event = threading.Event()
    ts.start_server(event, server)
    if server.announce:
        threading.Thread(
            target=server.announce_when_authenticated, daemon=True
        ).start()
    try:
        yield ts, server, sockc
    finally:
        ts.close()
        socks.close()
        sockc.close()


@pytest.fixture
def client_factory():
    """
    Make SSHClients (with optional known_hosts files) and close them all
    at the end of the test.
    """
    clients = []

    def make(user_path=None, system_path=None, policy=None):
        client = SSHClient()
        if system_path is not None:
            client.load_system_host_keys(str(system_path))
        if user_path is not None:
            client.load_host_keys(str(user_path))
        if policy is not None:
            client.set_missing_host_key_policy(policy)
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.close()


def connect(client, sockc, hostname=HOST, port=PORT, **kwargs):
    client.connect(
        hostname,
        port=port,
        username="slowdive",
        password=PASSWORD,
        sock=sockc,
        look_for_keys=False,
        allow_agent=False,
        **kwargs,
    )


def wait_for_announcement(client, count, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        announced = client.get_transport().get_announced_host_keys()
        if len(announced) >= count:
            return announced
        time.sleep(0.01)
    raise TimeoutError("server announced no host keys")


def blobs(keys):
    return {k.asbytes() for k in keys}


# ---------------------------------------------------------------------
# Requirement 1: learning is an opt-in entry point, off by default, and
# only allowed from a pre-trusted, authenticated connection.
# ---------------------------------------------------------------------


class TestLearningGates:
    def test_nothing_is_learned_by_default(self, tmp_path, client_factory):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        before = user.read_bytes()
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, server, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            # No learn_host_keys() call: the announcement alone must not
            # change anything, on disk or in memory.
            assert user.read_bytes() == before
            for key in NEW_KEYS:
                assert not client.get_host_keys().check(NAME, key)

    def test_learn_requires_connection(self, client_factory):
        client = client_factory()
        with pytest.raises(SSHException, match="not connected"):
            client.learn_host_keys()

    def test_learn_requires_pretrusted_handshake_key(
        self, tmp_path, client_factory
    ):
        # AutoAddPolicy accepts the unknown key on first use; that first
        # acceptance must not qualify as a starting point for learning.
        user = tmp_path / "known_hosts"
        user.write_text("")
        client = client_factory(user, policy=AutoAddPolicy())
        with rotation_server(ALL_SERVER_KEYS) as (ts, server, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            with pytest.raises(SSHException, match="previously loaded"):
                client.learn_host_keys()
            # Only the auto-added handshake key may be in the file.
            text = user.read_text()
            assert text.count("\n") == 1
            for key in NEW_KEYS:
                assert not client.get_host_keys().check(NAME, key)
        # ...but once the auto-added key *is* the pre-loaded trust anchor
        # of a later connection, learning becomes allowed.
        with rotation_server(ALL_SERVER_KEYS) as (ts, server, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            learned = client.learn_host_keys()
            assert blobs(learned) == blobs(NEW_KEYS)

    def test_learn_requires_completed_authentication(
        self, tmp_path, client_factory
    ):
        with rotation_server(ALL_SERVER_KEYS) as (ts, server, sockc):
            # Raw transport with no credentials: active, but no user auth.
            tc = Transport(sockc)
            tc.connect(username="slowdive")
            try:
                assert tc.is_active()
                assert not tc.is_authenticated()
                client = client_factory()
                client._transport = tc
                client._handshake_key_trusted = True
                client._server_hostkey_name = NAME
                with pytest.raises(SSHException, match="authentication"):
                    client.learn_host_keys()
            finally:
                tc.close()


# ---------------------------------------------------------------------
# Requirement 2: the announcement and proof-of-possession extensions;
# proofs bind session and key; the whole batch is rejected on any
# missing, tampered, replayed, or miscounted proof.
# ---------------------------------------------------------------------


class TestAnnouncementAndProof:
    def test_happy_path(self, tmp_path, client_factory):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, server, sockc):
            connect(client, sockc)
            announced = wait_for_announcement(client, len(ALL_SERVER_KEYS))
            assert blobs(announced) == blobs(ALL_SERVER_KEYS)
            learned = client.learn_host_keys()
            assert blobs(learned) == blobs(NEW_KEYS)
            for key in ALL_SERVER_KEYS:
                assert client.get_host_keys().check(NAME, key)

    def test_transport_level_announcement_and_proof(self, client_factory):
        # The Transport primitives directly: announcement is stored, and
        # proofs verify against this session.
        with rotation_server(ALL_SERVER_KEYS) as (ts, server, sockc):
            tc = Transport(sockc)
            tc.connect(username="slowdive", password=PASSWORD)
            try:
                deadline = time.time() + 5
                while not tc.get_announced_host_keys():
                    assert time.time() < deadline
                    time.sleep(0.01)
                announced = tc.get_announced_host_keys()
                assert blobs(announced) == blobs(ALL_SERVER_KEYS)
                proven = tc.prove_host_keys(announced)
                assert blobs(proven) == blobs(ALL_SERVER_KEYS)
                # A key the server does not hold cannot be proven.
                stranger = ECDSAKey.generate()
                with pytest.raises(HostKeyProofError):
                    tc.prove_host_keys([stranger])
            finally:
                tc.close()

    def test_missing_proofs_reject_batch(self, tmp_path, client_factory):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        before = user.read_bytes()
        client = client_factory(user)
        # Server returns one signature fewer than requested.
        with rotation_server(ALL_SERVER_KEYS, drop=1) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            with pytest.raises(HostKeyProofError, match="proof"):
                client.learn_host_keys()
        self._assert_nothing_learned(client, user, before)

    def test_extra_proofs_reject_batch(self, tmp_path, client_factory):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        before = user.read_bytes()
        client = client_factory(user)
        # Server returns more signatures than requested.
        with rotation_server(ALL_SERVER_KEYS, extra=1) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            with pytest.raises(HostKeyProofError, match="proof"):
                client.learn_host_keys()
        self._assert_nothing_learned(client, user, before)

    def test_tampered_proof_rejects_batch(self, tmp_path, client_factory):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        before = user.read_bytes()
        client = client_factory(user)
        # Server signs a transcript that is not the real proof transcript.
        with rotation_server(ALL_SERVER_KEYS, tamper=True) as (
            ts,
            sv,
            sockc,
        ):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            with pytest.raises(HostKeyProofError, match="proof failed"):
                client.learn_host_keys()
        self._assert_nothing_learned(client, user, before)

    def test_refused_proof_rejects_batch(self, tmp_path, client_factory):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        before = user.read_bytes()
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS, refuse=True) as (
            ts,
            sv,
            sockc,
        ):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            with pytest.raises(HostKeyProofError, match="refused"):
                client.learn_host_keys()
        self._assert_nothing_learned(client, user, before)

    def test_unprovable_announced_key_rejects_batch(
        self, tmp_path, client_factory
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        before = user.read_bytes()
        client = client_factory(user)
        # Server announces a key it does not possess.
        stranger = ECDSAKey.generate()
        with rotation_server(ALL_SERVER_KEYS, announce_extra=[stranger]) as (
            ts,
            sv,
            sockc,
        ):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS) + 1)
            with pytest.raises(HostKeyProofError):
                client.learn_host_keys()
        self._assert_nothing_learned(client, user, before)

    def test_cross_session_replay_rejects_batch(
        self, tmp_path, client_factory
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        before = user.read_bytes()
        # Session 1: honest server; capture its genuine proof signatures.
        client1 = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, server1, sockc):
            connect(client1, sockc)
            announced = wait_for_announcement(client1, len(ALL_SERVER_KEYS))
            new_announced = [
                k for k in announced if k.asbytes() != OLD.asbytes()
            ]
            client1.get_transport().prove_host_keys(new_announced)
            replay = list(server1.recorded_signatures)
            assert len(replay) == len(NEW_KEYS)
        # Session 2: a server replaying session 1's signatures verbatim.
        # The proofs are bound to session 1's session ID and must fail.
        client2 = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS, replay=replay) as (
            ts,
            server2,
            sockc,
        ):
            connect(client2, sockc)
            wait_for_announcement(client2, len(ALL_SERVER_KEYS))
            with pytest.raises(HostKeyProofError, match="proof failed"):
                client2.learn_host_keys()
        self._assert_nothing_learned(client2, user, before)

    def test_no_announcement_means_nothing_to_learn(
        self, tmp_path, client_factory
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS, announce=False) as (
            ts,
            sv,
            sockc,
        ):
            connect(client, sockc)
            assert client.learn_host_keys() == []
            assert user.read_text() == plain_line(NAME, OLD)

    def _assert_nothing_learned(self, client, user, before):
        assert user.read_bytes() == before
        for key in NEW_KEYS:
            assert not client.get_host_keys().check(NAME, key)


# ---------------------------------------------------------------------
# Requirement 3: learning only adds; old and new keys of the same host
# and algorithm both pass later checks, on disk and after reload;
# repeats do not duplicate.
# ---------------------------------------------------------------------


class TestAdditiveLearning:
    def test_old_and_new_same_algorithm_keys_both_pass(
        self, tmp_path, client_factory
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            client.learn_host_keys()
        # The same client object, using the ordinary connect() handshake
        # check, now accepts the server presenting *either* the old or
        # the new key of the same algorithm (ssh-rsa here).
        for presented in (OLD, NEW_RSA, NEW_ECDSA, NEW_ED):
            with rotation_server(
                [presented], handshake_keys=[presented], announce=False
            ) as (ts, sv, sockc):
                connect(client, sockc)
                assert client.get_transport().is_authenticated()

    def test_learned_keys_survive_save_and_reload(
        self, tmp_path, client_factory
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            client.learn_host_keys()
        # A fresh process view: load the file from disk.
        reloaded = HostKeys(str(user))
        for key in ALL_SERVER_KEYS:
            assert reloaded.check(NAME, key)
        # And a brand-new SSHClient using only that file connects fine
        # to a server that now presents a new key.
        client2 = client_factory(user)
        with rotation_server(
            [NEW_RSA], handshake_keys=[NEW_RSA], announce=False
        ) as (
            ts,
            sv,
            sockc,
        ):
            connect(client2, sockc)

    def test_repeat_learning_adds_no_duplicates(
        self, tmp_path, client_factory
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            first = client.learn_host_keys()
            assert len(first) == len(NEW_KEYS)
            after_first = user.read_bytes()
            # Same announcement again: nothing new to learn, no new lines.
            assert client.learn_host_keys() == []
            assert user.read_bytes() == after_first
        # A second connection re-announcing the same keys: still nothing.
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            assert client.learn_host_keys() == []
            assert user.read_bytes() == after_first
        # Exactly one line per key.
        lines = [x for x in user.read_text().splitlines() if x.strip()]
        assert len(lines) == 1 + len(NEW_KEYS)

    def test_save_host_keys_preserves_learned_keys(
        self, tmp_path, client_factory
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            client.learn_host_keys()
        # The classic save_host_keys() rewrite must not drop the learned
        # same-type keys either.
        elsewhere = tmp_path / "saved_elsewhere"
        client.save_host_keys(str(elsewhere))
        reloaded = HostKeys(str(elsewhere))
        for key in ALL_SERVER_KEYS:
            assert reloaded.check(NAME, key)

    def test_learning_without_associated_file_is_memory_only(
        self, client_factory
    ):
        # No load_host_keys(): the in-memory HostKeys are seeded directly
        # and learning publishes to memory only.
        client = client_factory()
        client.get_host_keys().add(NAME, OLD.get_name(), OLD)
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            learned = client.learn_host_keys()
            assert blobs(learned) == blobs(NEW_KEYS)
            for key in ALL_SERVER_KEYS:
                assert client.get_host_keys().check(NAME, key)


# ---------------------------------------------------------------------
# Requirement 4: Transport announcement/proof, HostKeys matching and
# SSHClient's handshake check all agree on the committed trusted set.
# ---------------------------------------------------------------------


class TestConsistency:
    def test_failed_proof_does_not_change_future_connections(
        self, tmp_path, client_factory
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS, tamper=True) as (
            ts,
            sv,
            sockc,
        ):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            with pytest.raises(HostKeyProofError):
                client.learn_host_keys()
        # A server presenting a new key is still rejected, exactly as
        # before the failed learning attempt.
        with rotation_server(
            [NEW_RSA], handshake_keys=[NEW_RSA], announce=False
        ) as (
            ts,
            sv,
            sockc,
        ):
            with pytest.raises(BadHostKeyException):
                connect(client, sockc)
        # While the old key still works.
        with rotation_server([OLD], announce=False) as (ts, sv, sockc):
            connect(client, sockc)

    def test_successful_learning_changes_original_handshake_check(
        self, tmp_path, client_factory
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        client = client_factory(user)
        # Before learning: the stock connect() check rejects the new key.
        with rotation_server(
            [NEW_RSA], handshake_keys=[NEW_RSA], announce=False
        ) as (
            ts,
            sv,
            sockc,
        ):
            with pytest.raises(BadHostKeyException):
                connect(client, sockc)
        # Learn over a connection anchored in the old key...
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            client.learn_host_keys()
        # ...and the very same connect() check now accepts the new key.
        with rotation_server(
            [NEW_RSA], handshake_keys=[NEW_RSA], announce=False
        ) as (
            ts,
            sv,
            sockc,
        ):
            connect(client, sockc)
            assert client.get_transport().is_authenticated()

    def test_hostkeys_check_accepts_any_matching_entry(self):
        hostkeys = HostKeys()
        assert hostkeys.add_if_absent("host", OLD) is True
        # Same host, same algorithm, different key: added alongside.
        assert hostkeys.add_if_absent("host", NEW_RSA) is True
        # Both match; the first was not replaced.
        assert hostkeys.check("host", OLD)
        assert hostkeys.check("host", NEW_RSA)
        # Genuine duplicates are refused.
        assert hostkeys.add_if_absent("host", OLD) is False
        assert hostkeys.add_if_absent("host", NEW_RSA) is False
        # An unknown key still does not match.
        stranger = ECDSAKey.generate()
        assert not hostkeys.check("host", stranger)
        # ...and neither does the right key for the wrong host.
        assert not hostkeys.check("elsewhere", OLD)

    def test_hostkeys_add_would_replace_but_learning_does_not(self):
        # Document the difference from HostKeys.add, which replaces.
        hostkeys = HostKeys()
        hostkeys.add("host", "ssh-rsa", OLD)
        hostkeys.add("host", "ssh-rsa", NEW_RSA)
        assert not hostkeys.check("host", OLD)
        assert hostkeys.check("host", NEW_RSA)

    def test_matching_entry_reports_storage_form(self):
        hostkeys = HostKeys()
        hostkeys.add("host", "ssh-rsa", OLD)
        entry = hostkeys.matching_entry("host", OLD)
        assert entry is not None
        assert entry.hostnames == ["host"]
        assert hostkeys.matching_entry("host", NEW_RSA) is None
        # Hashed entries are found too, and reveal their hashed form.
        hashed = HostKeys()
        hashed.add_if_absent(
            "host", OLD, storage_name=HostKeys.hash_host("host")
        )
        entry = hashed.matching_entry("host", OLD)
        assert entry is not None
        assert entry.hostnames[0].startswith("|1|")
        assert hashed.check("host", OLD)

    def test_hostkeys_roundtrip_through_file(self, tmp_path):
        path = tmp_path / "known_hosts"
        hostkeys = HostKeys()
        hostkeys.add_if_absent(NAME, OLD)
        hostkeys.add_if_absent(NAME, NEW_RSA)
        hostkeys.save(str(path))
        reloaded = HostKeys(str(path))
        assert reloaded.check(NAME, OLD)
        assert reloaded.check(NAME, NEW_RSA)


# ---------------------------------------------------------------------
# Requirement 5: updates are scoped to this connection's host and port;
# hashed hostnames and non-default ports work; combined lines do not
# leak keys to other hosts; the system file is never touched.
# ---------------------------------------------------------------------


class TestScoping:
    @pytest.mark.parametrize("port,expected_name", [(22, HOST), (2222, NAME)])
    def test_update_written_for_connection_host_and_port(
        self, tmp_path, client_factory, port, expected_name
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(expected_name, OLD))
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc, port=port)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            client.learn_host_keys()
        reloaded = HostKeys(str(user))
        for key in ALL_SERVER_KEYS:
            assert reloaded.check(expected_name, key)
        if port != 22:
            # The bare hostname (i.e. port 22) must NOT trust the keys.
            for key in NEW_KEYS:
                assert not reloaded.check(HOST, key)
            # ...and the file literally scopes them to [host]:port.
            for line in user.read_text().splitlines():
                if NEW_RSA.get_base64() in line:
                    assert line.startswith(NAME)

    def test_hashed_hostname_stays_hashed(self, tmp_path, client_factory):
        user = tmp_path / "known_hosts"
        user.write_text(hashed_line(NAME, OLD))
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            learned = client.learn_host_keys()
            assert blobs(learned) == blobs(NEW_KEYS)
        lines = user.read_text().splitlines()
        assert len(lines) == 1 + len(NEW_KEYS)
        new_lines = [x for x in lines if NEW_RSA.get_base64() in x]
        assert len(new_lines) == 1
        # The new line is hashed and does not leak the cleartext name.
        assert new_lines[0].startswith("|1|")
        assert HOST not in new_lines[0]
        # Everything still resolves and matches after reload.
        reloaded = HostKeys(str(user))
        for key in ALL_SERVER_KEYS:
            assert reloaded.check(NAME, key)

    def test_combined_line_does_not_leak_to_other_hosts(
        self, tmp_path, client_factory
    ):
        other = "other.example.com"
        user = tmp_path / "known_hosts"
        # One combined line covering both our server and another host.
        combined = "{},{} {} {}\n".format(
            other, NAME, OLD.get_name(), OLD.get_base64()
        )
        user.write_text(combined)
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            client.learn_host_keys()
        reloaded = HostKeys(str(user))
        # Our host trusts the new keys...
        for key in ALL_SERVER_KEYS:
            assert reloaded.check(NAME, key)
        # ...but the other host on the combined line does not.
        for key in NEW_KEYS:
            assert not reloaded.check(other, key)
        # The original combined line is preserved byte-for-byte, and the
        # other host's name appears nowhere else.
        text = user.read_text()
        assert combined in text
        assert text.count(other) == 1

    def test_system_file_is_never_modified(self, tmp_path, client_factory):
        system = tmp_path / "system_known_hosts"
        system.write_text(plain_line(NAME, OLD))
        system_before = system.read_bytes()
        user = tmp_path / "known_hosts"
        user.write_text("")
        client = client_factory(user, system_path=system)
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            learned = client.learn_host_keys()
            assert blobs(learned) == blobs(NEW_KEYS)
        # The read-only system file is untouched; the user file got the
        # new keys.
        assert system.read_bytes() == system_before
        reloaded = HostKeys(str(user))
        for key in NEW_KEYS:
            assert reloaded.check(NAME, key)


# ---------------------------------------------------------------------
# Requirement 6: concurrent learners committing to the same user file
# never lose each other's keys, nor unrelated changes.
# ---------------------------------------------------------------------


class TestConcurrentCommit:
    def _learn_in_thread(self, client, keys, barrier, results, tag):
        with rotation_server(keys) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(keys))
            barrier.wait(timeout=10)
            results[tag] = client.learn_host_keys()

    def test_simultaneous_learners_keep_all_committed_keys(
        self, tmp_path, client_factory
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        client_a = client_factory(user)
        client_b = client_factory(user)
        barrier = threading.Barrier(2)
        results = {}
        threads = [
            threading.Thread(
                target=self._learn_in_thread,
                args=(client_a, [OLD, NEW_RSA], barrier, results, "a"),
            ),
            threading.Thread(
                target=self._learn_in_thread,
                args=(client_b, [OLD, NEW_ECDSA], barrier, results, "b"),
            ),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        assert blobs(results["a"]) == {NEW_RSA.asbytes()}
        assert blobs(results["b"]) == {NEW_ECDSA.asbytes()}
        # Both increments for the same host survived in the shared file.
        reloaded = HostKeys(str(user))
        for key in (OLD, NEW_RSA, NEW_ECDSA):
            assert reloaded.check(NAME, key)
        # Each client published its own proven keys in memory.
        assert client_a.get_host_keys().check(NAME, NEW_RSA)
        assert client_b.get_host_keys().check(NAME, NEW_ECDSA)

    def test_interleaved_commits_preserve_other_hosts_changes(
        self, tmp_path, client_factory, monkeypatch
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        client_a = client_factory(user)
        client_b = client_factory(user)
        # Force both learners to finish their proofs and reach the commit
        # point, then let a third party modify the file, and only then
        # allow the commits to run (in either order).
        proved = threading.Barrier(3)
        external_written = threading.Barrier(3)
        real_update = update_known_hosts_file

        def gated_update(filename, additions):
            proved.wait(timeout=10)
            external_written.wait(timeout=10)
            return real_update(filename, additions)

        monkeypatch.setattr(
            "paramiko.client.update_known_hosts_file", gated_update
        )
        results = {}
        barrier = threading.Barrier(2)
        threads = [
            threading.Thread(
                target=self._learn_in_thread,
                args=(client_a, [OLD, NEW_RSA], barrier, results, "a"),
            ),
            threading.Thread(
                target=self._learn_in_thread,
                args=(client_b, [OLD, NEW_ECDSA], barrier, results, "b"),
            ),
        ]
        for t in threads:
            t.start()
        # Both clients proved their keys and are parked at the commit.
        proved.wait(timeout=10)
        # An unrelated actor edits the file "meanwhile".
        with open(user, "a") as f:
            f.write(plain_line("unrelated.example.com", NEW_ED))
        external_written.wait(timeout=10)
        for t in threads:
            t.join(30)
        assert blobs(results["a"]) == {NEW_RSA.asbytes()}
        assert blobs(results["b"]) == {NEW_ECDSA.asbytes()}
        reloaded = HostKeys(str(user))
        # Both clients' increments for the same host...
        for key in (OLD, NEW_RSA, NEW_ECDSA):
            assert reloaded.check(NAME, key)
        # ...and the unrelated host's modification all survived.
        assert reloaded.check("unrelated.example.com", NEW_ED)


# ---------------------------------------------------------------------
# Requirement 7: a failed commit fails the call loudly and changes
# nothing -- neither the file nor the published in-memory trust set --
# and a later attempt still succeeds.
# ---------------------------------------------------------------------


class TestCommitFailure:
    def _run_failure_scenario(
        self, tmp_path, client_factory, monkeypatch, target, replacement
    ):
        user = tmp_path / "known_hosts"
        user.write_text(plain_line(NAME, OLD))
        before = user.read_bytes()
        client = client_factory(user)
        with rotation_server(ALL_SERVER_KEYS) as (ts, sv, sockc):
            connect(client, sockc)
            wait_for_announcement(client, len(ALL_SERVER_KEYS))
            monkeypatch.setattr(target, replacement)
            with pytest.raises(OSError, match="injected"):
                client.learn_host_keys()
            monkeypatch.undo()
            # The original file is byte-identical...
            assert user.read_bytes() == before
            # ...no temp files were left behind...
            leftovers = [
                p
                for p in os.listdir(tmp_path)
                if p.startswith(".known_hosts-")
            ]
            assert leftovers == []
            # ...and the in-memory trusted set was not published either.
            for key in NEW_KEYS:
                assert not client.get_host_keys().check(NAME, key)
            # The next attempt on the same connection succeeds.
            learned = client.learn_host_keys()
            assert blobs(learned) == blobs(NEW_KEYS)
            reloaded = HostKeys(str(user))
            for key in ALL_SERVER_KEYS:
                assert reloaded.check(NAME, key)

    def test_replace_failure(self, tmp_path, client_factory, monkeypatch):
        import os as real_os

        real_replace = real_os.replace
        user_str = str(tmp_path / "known_hosts")

        def failing_replace(src, dst):
            if dst == user_str:
                raise OSError("injected replace failure")
            return real_replace(src, dst)

        self._run_failure_scenario(
            tmp_path,
            client_factory,
            monkeypatch,
            "os.replace",
            failing_replace,
        )

    def test_write_failure(self, tmp_path, client_factory, monkeypatch):
        import tempfile as real_tempfile

        real_mkstemp = real_tempfile.mkstemp

        def failing_mkstemp(*args, **kwargs):
            if kwargs.get("dir") == str(tmp_path):
                raise OSError("injected write failure")
            return real_mkstemp(*args, **kwargs)

        self._run_failure_scenario(
            tmp_path,
            client_factory,
            monkeypatch,
            "tempfile.mkstemp",
            failing_mkstemp,
        )


# ---------------------------------------------------------------------
# Requirement 8 (mechanics): the commit helper merges additively,
# preserves existing bytes, dedupes against the committed set, and only
# then may trust be published.
# ---------------------------------------------------------------------


class TestCommitHelper:
    def test_appends_to_missing_file_with_private_mode(self, tmp_path):
        path = tmp_path / "known_hosts"
        appended = update_known_hosts_file(str(path), [(NAME, NAME, NEW_RSA)])
        assert blobs([k for _, k in appended]) == {NEW_RSA.asbytes()}
        assert HostKeys(str(path)).check(NAME, NEW_RSA)
        mode = os.stat(str(path)).st_mode & 0o777
        assert mode == 0o600

    def test_preserves_existing_bytes_and_appends(self, tmp_path):
        path = tmp_path / "known_hosts"
        original = (
            "# a comment\n"
            + "hosta,hostb {} {}\n".format(OLD.get_name(), OLD.get_base64())
            + plain_line(NAME, OLD)
        )
        path.write_text(original)
        appended = update_known_hosts_file(str(path), [(NAME, NAME, NEW_RSA)])
        assert len(appended) == 1
        text = path.read_text()
        assert text.startswith(original)
        assert text.endswith(
            "{} {} {}\n".format(NAME, NEW_RSA.get_name(), NEW_RSA.get_base64())
        )

    def test_dedupes_against_committed_set(self, tmp_path):
        path = tmp_path / "known_hosts"
        path.write_text(plain_line(NAME, OLD))
        # Already present (exact key): nothing appended, file untouched.
        before = path.read_bytes()
        assert update_known_hosts_file(str(path), [(NAME, NAME, OLD)]) == []
        assert path.read_bytes() == before
        # Present via a hashed entry: still deduped.
        hashed_path = tmp_path / "hashed_known_hosts"
        hashed_path.write_text(hashed_line(NAME, NEW_RSA))
        before = hashed_path.read_bytes()
        storage = HostKeys.hash_host(NAME)
        assert (
            update_known_hosts_file(
                str(hashed_path), [(NAME, storage, NEW_RSA)]
            )
            == []
        )
        assert hashed_path.read_bytes() == before

    def test_file_lock_is_released_between_commits(self, tmp_path):
        path = tmp_path / "known_hosts"
        path.write_text(plain_line(NAME, OLD))
        update_known_hosts_file(str(path), [(NAME, NAME, NEW_RSA)])
        update_known_hosts_file(str(path), [(NAME, NAME, NEW_ECDSA)])
        reloaded = HostKeys(str(path))
        for key in (OLD, NEW_RSA, NEW_ECDSA):
            assert reloaded.check(NAME, key)
