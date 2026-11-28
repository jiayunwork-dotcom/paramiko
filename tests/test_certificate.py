# Copyright (C) 2026 Paramiko Authors
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Tests for OpenSSH user certificate parsing and server-side validation.

All fixtures live under tests/_support/certs and were generated offline with
ssh-keygen; no external CA or real SSH server is required.
"""

import base64
import threading

from pytest import raises

from paramiko import (
    AUTH_FAILED,
    AUTH_SUCCESSFUL,
    ECDSAKey,
    Ed25519Key,
    RSAKey,
    ServerInterface,
    Transport,
)
from paramiko.certificate import (
    CertificateError,
    CertificateValidator,
    InvalidCertificate,
    OpenSSHCertificate,
    UntrustedCertificate,
)

from ._loop import LoopSocket
from ._util import _support

CERTS = "certs"


def _cert_blob(name):
    with open(_support(f"{CERTS}/{name}")) as fd:
        return base64.b64decode(fd.readline().split()[1])


def _ca_key(name):
    with open(_support(f"{CERTS}/{name}")) as fd:
        key_type, b64 = fd.readline().split()[:2]
    raw = base64.b64decode(b64)
    if key_type == "ssh-ed25519":
        return Ed25519Key(data=raw)
    if key_type == "ssh-rsa":
        return RSAKey(data=raw)
    return ECDSAKey(data=raw)


def _user_ed25519_private():
    return Ed25519Key.from_private_key_file(
        _support(f"{CERTS}/user_ed25519")
    )


class TestOpenSSHCertificate:
    def test_parses_all_supported_key_types(self):
        for name, key_cls in (
            ("user_ed25519-cert.pub", Ed25519Key),
            ("user_rsa-cert.pub", RSAKey),
            ("user_ecdsa-cert.pub", ECDSAKey),
        ):
            cert = OpenSSHCertificate.from_blob(_cert_blob(name))
            assert isinstance(cert.key, key_cls)
            assert cert.is_user_certificate()
            assert cert.certificate_type == 1
            assert cert.signature
            assert cert.signature_key_type

    def test_exposes_principals_validity_and_key_id(self):
        cert = OpenSSHCertificate.from_blob(
            _cert_blob("user_ed25519-cert.pub")
        )
        assert cert.key_id == "ed25519-user-valid"
        assert cert.principals == ["alice"]
        assert cert.serial == 1001
        assert cert.valid_after < cert.valid_before
        assert cert.valid_at()

    def test_rejects_garbage_and_non_cert_blobs(self):
        with raises(InvalidCertificate):
            OpenSSHCertificate.from_blob(b"not a certificate")
        with raises(InvalidCertificate):
            OpenSSHCertificate.from_blob(b"")

    def test_rejects_arbitrary_trailing_junk(self):
        blob = bytearray(_cert_blob("user_ed25519-cert.pub"))
        # An outer string whose content cannot itself be parsed as an
        # algorithm+signature pair.
        blob.extend(b"\x00\x00\x00\x04junk")
        with raises((InvalidCertificate, CertificateError)):
            OpenSSHCertificate.from_blob(bytes(blob))

    def test_rejects_truncated_blob(self):
        # Cutting into the signature section either fails structural parsing
        # or, if the length prefix happens to survive, fails trust
        # verification because the signature bytes are incomplete.
        blob = _cert_blob("user_ed25519-cert.pub")
        ca = _ca_key("test_ed25519_ca.pub")
        validator = CertificateValidator([ca])
        rejected = False
        for cut in (10, 20, 40):
            try:
                cert = OpenSSHCertificate.from_blob(blob[:-cut])
                validator.validate(cert, "alice")
            except CertificateError:
                rejected = True
        assert rejected

    def test_from_public_blob_rejects_plain_key_blobs(self):
        from paramiko.pkey import PublicBlob

        plain = PublicBlob(
            "ssh-ed25519", _cert_blob("user_ed25519-cert.pub")[:40]
        )
        with raises(InvalidCertificate):
            OpenSSHCertificate.from_public_blob(plain)

    def test_equality_uses_blob_identity(self):
        blob = _cert_blob("user_ed25519-cert.pub")
        assert OpenSSHCertificate.from_blob(blob) == (
            OpenSSHCertificate.from_blob(blob)
        )

    def test_decodes_force_command_critical_option(self):
        cert = OpenSSHCertificate.from_blob(
            _cert_blob("user_ed25519_forcecmd-cert.pub")
        )
        assert cert.force_command() == "/bin/true"
        assert cert.source_addresses() is None

    def test_decodes_source_addresses_as_networks(self):
        import ipaddress

        cert = OpenSSHCertificate.from_blob(
            _cert_blob("user_ed25519_srcaddr-cert.pub")
        )
        networks = cert.source_addresses()
        assert ipaddress.ip_address("127.0.0.1") in networks[0]
        assert ipaddress.ip_address("10.1.2.3") in networks[1]
        assert ipaddress.ip_address("8.8.8.8") not in networks[0]
        assert cert.force_command() is None

    def test_absent_critical_options_report_none(self):
        cert = OpenSSHCertificate.from_blob(
            _cert_blob("user_ed25519-cert.pub")
        )
        assert cert.force_command() is None
        assert cert.source_addresses() is None

    def test_principal_match_is_exact_and_case_sensitive(self):
        cert = OpenSSHCertificate.from_blob(
            _cert_blob("user_ed25519-cert.pub")
        )
        assert cert.has_principal("alice")
        assert not cert.has_principal("Alice")
        assert not cert.has_principal("alice2")
        assert not cert.has_principal("ali")

    def test_validity_window_bounds_are_half_open(self):
        cert = OpenSSHCertificate.from_blob(
            _cert_blob("user_ed25519-cert.pub")
        )
        assert cert.valid_at(cert.valid_after)
        assert not cert.valid_at(cert.valid_before)
        assert not cert.valid_at(cert.valid_after - 1)


class TestCertificateValidator:
    def setup_method(self):
        self.ed_ca = _ca_key("test_ed25519_ca.pub")
        self.rsa_ca = _ca_key("test_rsa_ca.pub")
        self.other_rsa_ca = _ca_key("test_other_rsa_ca.pub")

    def test_ed25519_cert_validates_and_records_signing_ca(self):
        validator = CertificateValidator([self.ed_ca])
        cert = validator.validate(
            _cert_blob("user_ed25519-cert.pub"), "alice"
        )
        assert cert.signing_ca == self.ed_ca

    def test_rsa_ca_validates_rsa_and_cross_type_ecdsa_certs(self):
        validator = CertificateValidator([self.rsa_ca])
        assert validator.validate(
            _cert_blob("user_rsa-cert.pub"), "bob"
        ).signing_ca == self.rsa_ca
        # ECDSA user key signed by an RSA CA: signature algorithm must match
        # the CA key, and the embedded ECDSA key is still parsed correctly.
        cross = validator.validate(
            _cert_blob("user_ecdsa-cert.pub"), "carol"
        )
        assert cross.signing_ca == self.rsa_ca
        assert isinstance(cross.key, ECDSAKey)

    def test_accepts_preparsed_certificate_objects(self):
        cert = OpenSSHCertificate.from_blob(
            _cert_blob("user_ed25519-cert.pub")
        )
        validator = CertificateValidator([self.ed_ca])
        assert validator.validate(cert, "alice") is cert

    def test_callable_ca_provider_is_consulted_per_user(self):
        valid_blob = _cert_blob("user_ed25519-cert.pub")
        seen_users = []

        def provider(username):
            seen_users.append(username)
            return [self.ed_ca] if username == "alice" else []

        validator = CertificateValidator(provider)
        assert validator.validate(valid_blob, "alice")
        assert seen_users == ["alice"]
        # The same callback consulted for another user yields no trusted CA.
        assert validator.trusted_ca_keys("nobody") == ()

    def test_callable_provider_returning_no_ca_rejects(self):
        validator = CertificateValidator(lambda username: [])
        with raises(UntrustedCertificate, match="No trusted CA"):
            validator.validate(
                _cert_blob("user_ed25519-cert.pub"), "alice"
            )

    def test_expired_certificate_rejected(self):
        validator = CertificateValidator([self.ed_ca])
        with raises(InvalidCertificate, match="validity"):
            validator.validate(
                _cert_blob("user_ed25519_expired-cert.pub"), "alice"
            )

    def test_future_certificate_rejected(self):
        validator = CertificateValidator([self.ed_ca])
        with raises(InvalidCertificate, match="validity"):
            validator.validate(
                _cert_blob("user_ed25519_future-cert.pub"), "alice"
            )

    def test_principal_mismatch_rejected(self):
        validator = CertificateValidator([self.ed_ca])
        with raises(InvalidCertificate, match="[Pp]rincipal"):
            validator.validate(
                _cert_blob("user_ed25519_wrongprinc-cert.pub"), "alice"
            )

    def test_host_certificate_rejected_for_user_auth(self):
        validator = CertificateValidator([self.ed_ca])
        with raises(InvalidCertificate, match="host certificate"):
            validator.validate(
                _cert_blob("user_ed25519_host-cert.pub"), "alice"
            )

    def test_unknown_critical_option_rejected(self):
        validator = CertificateValidator([self.ed_ca])
        with raises(InvalidCertificate, match="critical options"):
            validator.validate(
                _cert_blob("user_ed25519_unknowncrit-cert.pub"), "alice"
            )

    def test_untrusted_ca_rejected(self):
        # Signed by test_other_rsa_ca, but a different RSA CA is trusted.
        validator = CertificateValidator([self.rsa_ca])
        with raises(UntrustedCertificate):
            validator.validate(
                _cert_blob("user_rsa_untrusted-cert.pub"), "bob"
            )

    def test_no_configured_cas_rejected(self):
        validator = CertificateValidator([])
        with raises(UntrustedCertificate, match="No trusted CA"):
            validator.validate(
                _cert_blob("user_ed25519-cert.pub"), "alice"
            )

    def test_signature_algorithm_family_mismatch_rejected(self):
        # Ed25519-signed cert can never validate against RSA CA keys.
        validator = CertificateValidator([self.rsa_ca, self.other_rsa_ca])
        with raises(UntrustedCertificate):
            validator.validate(
                _cert_blob("user_ed25519-cert.pub"), "alice"
            )

    def test_ca_signature_algorithm_must_match_ca_key_family(self):
        from paramiko.certificate import (
            _signature_algorithm_matches_key,
        )

        rsa = self.rsa_ca
        ed = self.ed_ca
        # RSA CA may use the RSA algorithm family only.
        assert _signature_algorithm_matches_key("rsa-sha2-512", rsa)
        assert _signature_algorithm_matches_key("rsa-sha2-256", rsa)
        assert not _signature_algorithm_matches_key("ssh-ed25519", rsa)
        # Ed25519 CA only ever uses ssh-ed25519.
        assert _signature_algorithm_matches_key("ssh-ed25519", ed)
        assert not _signature_algorithm_matches_key("rsa-sha2-256", ed)
        # An ECDSA CA is bound to its own curve's algorithm.
        ecdsa_ca = ECDSAKey.generate()
        assert _signature_algorithm_matches_key(
            ecdsa_ca.get_name(), ecdsa_ca
        )
        assert not _signature_algorithm_matches_key(
            "ssh-ed25519", ecdsa_ca
        )

    def test_tampered_signature_rejected(self):
        blob = bytearray(_cert_blob("user_ed25519-cert.pub"))
        blob[-5] ^= 0xFF  # inside the final CA signature
        validator = CertificateValidator([self.ed_ca])
        with raises(UntrustedCertificate):
            validator.validate(bytes(blob), "alice")

    def test_tampered_signed_body_rejected(self):
        blob = bytearray(_cert_blob("user_ed25519-cert.pub"))
        blob[120] ^= 0xFF  # inside the region covered by the signature
        validator = CertificateValidator([self.ed_ca])
        with raises((UntrustedCertificate, InvalidCertificate)):
            validator.validate(bytes(blob), "alice")

    def test_source_address_helper_allows_without_option(self):
        validator = CertificateValidator([self.ed_ca])
        cert = validator.validate(
            _cert_blob("user_ed25519-cert.pub"), "alice"
        )
        assert validator.check_source_address(cert, "8.8.8.8")

    def test_source_address_helper_enforces_networks(self):
        validator = CertificateValidator([self.ed_ca])
        cert = OpenSSHCertificate.from_blob(
            _cert_blob("user_ed25519_srcaddr-cert.pub")
        )
        assert validator.check_source_address(cert, "127.0.0.1")
        assert validator.check_source_address(cert, "10.9.9.9")
        assert not validator.check_source_address(cert, "192.0.2.1")
        assert not validator.check_source_address(cert, "not-an-ip")

    def test_injected_clock_drives_validity_decision(self):
        cert = OpenSSHCertificate.from_blob(
            _cert_blob("user_ed25519-cert.pub")
        )
        # A clock frozen inside the window accepts.
        good = CertificateValidator(
            [self.ed_ca], now=lambda: cert.valid_after + 1
        )
        good.validate(_cert_blob("user_ed25519-cert.pub"), "alice")
        # A clock frozen past the end rejects.
        stale = CertificateValidator(
            [self.ed_ca], now=lambda: cert.valid_before + 1
        )
        with raises(InvalidCertificate, match="validity"):
            stale.validate(
                _cert_blob("user_ed25519-cert.pub"), "alice"
            )

    def test_empty_principal_list_is_wildcard(self):
        # OpenSSH treats a zero-principal certificate as matching any user.
        cert = OpenSSHCertificate.from_blob(
            _cert_blob("user_ed25519-cert.pub")
        )
        cert.principals = []
        assert cert.has_principal("anyone-at-all")


class _RecordingServer(ServerInterface):
    def __init__(self, accept_certs=True, accept_bare=None):
        self.seen = []
        self._accept_certs = accept_certs
        self._accept_bare = accept_bare or []

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        self.seen.append(key)
        if key.certificate is not None:
            return (
                AUTH_SUCCESSFUL if self._accept_certs else AUTH_FAILED
            )
        return (
            AUTH_SUCCESSFUL if key in self._accept_bare else AUTH_FAILED
        )


class TestServerCertificateAuth:
    """End-to-end checks over an in-process loopback transport."""

    def _pair(self, validator=None, server=None):
        socks, sockc = LoopSocket(), LoopSocket()
        sockc.link(socks)
        ts = Transport(socks)
        ts.add_server_key(RSAKey.generate(2048))
        if validator is not None:
            ts.set_certificate_validator(validator)
        if server is None:
            server = _RecordingServer()
        event = threading.Event()
        ts.start_server(event, server)
        tc = Transport(sockc)
        tc.start_client()
        return tc, ts, event, server

    def _auth(self, tc, ts, event, key, username):
        try:
            tc.auth_publickey(username, key)
            client_ok = True
        except Exception:
            client_ok = False
        event.wait(2)
        return client_ok, ts.is_authenticated()

    def _cert_key(self, priv, cert):
        key = Ed25519Key.from_private_key_file(
            _support(f"{CERTS}/{priv}")
        )
        key.load_certificate(_support(f"{CERTS}/{cert}"))
        return key

    def test_trusted_valid_cert_authenticates_and_reaches_callback(self):
        ca = _ca_key("test_ed25519_ca.pub")
        tc, ts, event, server = self._pair(CertificateValidator([ca]))
        key = self._cert_key("user_ed25519", "user_ed25519-cert.pub")
        ok, authed = self._auth(tc, ts, event, key, "alice")
        assert ok and authed
        assert len(server.seen) == 1
        presented = server.seen[0]
        # The callback sees the exact parsed object the library validated.
        assert presented.certificate.key_id == "ed25519-user-valid"
        assert presented.certificate.principals == ["alice"]
        assert presented.certificate.signing_ca == ca
        tc.close()
        ts.close()

    def test_proof_of_possession_still_required(self):
        # The certificate is trusted, but offering it alongside a private
        # key that does not match the certified public key must fail.
        import nacl.signing

        from paramiko.message import Message
        from paramiko.pkey import PublicBlob

        ca = _ca_key("test_ed25519_ca.pub")
        tc, ts, event, server = self._pair(CertificateValidator([ca]))
        unrelated = nacl.signing.SigningKey.generate()
        # Build a usable key from the unrelated pair using its proper SSH
        # public blob, then attach the (mismatched) trusted certificate.
        pub_blob = Message()
        pub_blob.add_string("ssh-ed25519")
        pub_blob.add_string(unrelated.verify_key.encode())
        wrong = Ed25519Key(data=pub_blob.asbytes())
        wrong._signing_key = unrelated
        wrong.public_blob = PublicBlob(
            "ssh-ed25519-cert-v01@openssh.com",
            _cert_blob("user_ed25519-cert.pub"),
        )
        ok, authed = self._auth(tc, ts, event, wrong, "alice")
        assert not ok and not authed
        tc.close()
        ts.close()

    def test_cert_without_validator_rejected_without_bare_fallback(self):
        bare = _user_ed25519_private()
        # The underlying bare key would be accepted; the unvalidated
        # certificate must nevertheless fail and never reach the callback.
        tc, ts, event, server = self._pair(
            validator=None, server=_RecordingServer(accept_bare=[bare])
        )
        key = self._cert_key("user_ed25519", "user_ed25519-cert.pub")
        ok, authed = self._auth(tc, ts, event, key, "alice")
        assert not ok and not authed
        assert server.seen == []
        tc.close()
        ts.close()

    def test_bare_key_path_is_unchanged(self):
        bare = _user_ed25519_private()
        tc, ts, event, server = self._pair(
            validator=CertificateValidator([_ca_key("test_ed25519_ca.pub")]),
            server=_RecordingServer(accept_bare=[bare]),
        )
        ok, authed = self._auth(tc, ts, event, bare, "alice")
        assert ok and authed
        assert server.seen[0].certificate is None
        tc.close()
        ts.close()

    def test_failed_cert_never_uses_bare_key_acceptance(self):
        bare = _user_ed25519_private()
        tc, ts, event, server = self._pair(
            validator=CertificateValidator([_ca_key("test_ed25519_ca.pub")]),
            server=_RecordingServer(accept_bare=[bare]),
        )
        key = self._cert_key(
            "user_ed25519", "user_ed25519_expired-cert.pub"
        )
        ok, authed = self._auth(tc, ts, event, key, "alice")
        assert not ok and not authed
        assert server.seen == []
        tc.close()
        ts.close()

    def test_callback_may_still_reject_a_validated_cert(self):
        ca = _ca_key("test_ed25519_ca.pub")
        tc, ts, event, server = self._pair(
            CertificateValidator([ca]),
            server=_RecordingServer(accept_certs=False),
        )
        key = self._cert_key(
            "user_ed25519", "user_ed25519_forcecmd-cert.pub"
        )
        ok, authed = self._auth(tc, ts, event, key, "alice")
        assert not ok and not authed
        # Validation passed, so the callback ran and saw the critical option.
        assert server.seen[0].certificate.force_command() == "/bin/true"
        tc.close()
        ts.close()

    def test_critical_options_are_visible_when_accepted(self):
        ca = _ca_key("test_ed25519_ca.pub")
        tc, ts, event, server = self._pair(CertificateValidator([ca]))
        key = self._cert_key(
            "user_ed25519", "user_ed25519_srcaddr-cert.pub"
        )
        ok, authed = self._auth(tc, ts, event, key, "alice")
        assert ok and authed
        networks = server.seen[0].certificate.source_addresses()
        assert [str(n) for n in networks] == [
            "127.0.0.1/32",
            "10.0.0.0/8",
        ]
        tc.close()
        ts.close()


class TestTransportTrustStoreAPI:
    def test_add_trusted_ca_key_installs_validator_and_accumulates(self):
        socks, sockc = LoopSocket(), LoopSocket()
        sockc.link(socks)
        ts = Transport(socks)
        assert ts.certificate_validator is None
        first = ts.add_trusted_ca_key(_ca_key("test_ed25519_ca.pub"))
        assert ts.certificate_validator is first
        assert first.trusted_ca_keys() == (_ca_key("test_ed25519_ca.pub"),)
        second = ts.add_trusted_ca_key(_ca_key("test_rsa_ca.pub"))
        # Same validator instance, now holding both CAs.
        assert second is first
        assert len(second.trusted_ca_keys()) == 2
        ts.close()
        sockc.close()
        socks.close()

    def test_set_certificate_validator_replaces_default(self):
        socks, sockc = LoopSocket(), LoopSocket()
        sockc.link(socks)
        ts = Transport(socks)
        ts.add_trusted_ca_key(_ca_key("test_ed25519_ca.pub"))
        custom = CertificateValidator([_ca_key("test_rsa_ca.pub")])
        ts.set_certificate_validator(custom)
        assert ts.certificate_validator is custom
        ts.close()
        sockc.close()
        socks.close()
