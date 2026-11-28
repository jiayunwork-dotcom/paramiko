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
OpenSSH user certificate parsing and server-side validation.

OpenSSH certificate format reference:
https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys

A certificate is, on the wire, a single SSH string blob whose first field is
a ``*-cert-v01@openssh.com`` key type.  Paramiko already knew how to carry
such blobs around (`.PublicBlob`, ``PKey.public_blob``) so that clients could
*offer* certificates; this module teaches the library how to *parse and
verify* them so servers do not have to treat them as opaque key material.

The entry points are:

- `.OpenSSHCertificate` -- a parsed view of a certificate blob, including
  principals, validity window, critical options, extensions and the embedded
  CA signature.
- `.CertificateValidator` -- performs the full server-side trust check
  (user-certificate type, trusted CA, signature/algorithm match, validity
  period, exact principal match and known critical options).
"""

import ipaddress
import time
from datetime import datetime, timezone

from paramiko.message import Message
from paramiko.ssh_exception import SSHException
from paramiko.util import u

#: Certificates whose ``type`` field equals this value are user certificates
#: (the only kind acceptable for SSH user authentication).
SSH_CERT_TYPE_USER = 1
#: Host certificates are rejected during user authentication.
SSH_CERT_TYPE_HOST = 2

# Critical options defined by OpenSSH.  Anything else is, per the spec, an
# unknown critical option and must cause rejection.
_KNOWN_CRITICAL_OPTIONS = ("force-command", "source-address")

# The certificate key-type prefixes this parser understands. Whether the
# embedded CA signature matches a given trusted CA key is enforced separately
# by _signature_algorithm_matches_key().
_CERT_TYPE_PREFIXES = (
    "ssh-rsa-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com",
)


class CertificateError(SSHException):
    """
    A certificate blob could not be parsed, or failed a validation check.

    During server-side public key authentication any such failure is treated
    as an authentication failure: the unvalidated certificate is never handed
    to the regular public-key callback.
    """


class InvalidCertificate(CertificateError):
    """
    The certificate data itself is malformed or internally inconsistent.
    """


class UntrustedCertificate(CertificateError):
    """
    The certificate was not signed by a configured trusted CA, or its
    signature could not be verified (including algorithm mismatches).
    """


def _parse_cert_map(blob):
    """
    Decode one of the certificate's zero-or-more name/value maps.

    Both critical options and extensions are encoded as an outer SSH string
    containing repeated ``name`` + inner-value-string pairs.
    """
    result = {}
    message = Message(blob)
    while message.get_remainder():
        name = message.get_text()
        # Values are themselves SSH strings (often empty for extensions).
        value = message.get_binary()
        # Critical-option values wrap another layer of string encoding in the
        # on-disk format; leave the raw inner blob alone here, callers decode.
        result[name] = value
    return result


def _parse_principals(blob):
    message = Message(blob)
    principals = []
    while message.get_remainder():
        principals.append(message.get_text())
    return principals


class OpenSSHCertificate:
    """
    Parsed representation of an OpenSSH ``*-cert-v01@openssh.com`` blob.

    Instances are produced by `.from_blob` (or, equivalently for convenience,
    by passing a `.PublicBlob`).  The same parsed object is used both for the
    library's own trust checks and for the data handed to server callbacks,
    so a callback can never interpret a different copy of the bytes than the
    one that was validated.

    Attributes:

    - ``key_type``: certificate type identifier, e.g.
      ``"ssh-ed25519-cert-v01@openssh.com"``.
    - ``nonce``: the certificate nonce (`bytes`).
    - ``key``: the underlying public key as a `.PKey` instance.
    - ``serial``: 64-bit serial number.
    - ``certificate_type``: ``1`` for user certs, ``2`` for host certs.
    - ``key_id``: free-form key identifier `str`.
    - ``principals``: list of principal name `str` values.
    - ``valid_after`` / ``valid_before``: validity window as UTC Unix
      timestamps (`int`); ``0`` and ``2**64 - 1`` mean the open bounds.
    - ``critical_options``: dict mapping option name (`str`) to raw inner
      value `bytes` (empty bytes for valueless options).
    - ``extensions``: dict mapping extension name to raw value `bytes`.
    - ``signature_key_type``: algorithm name embedded in the CA signature.
    - ``signature``: the raw CA signature `bytes`.
    - ``blob``: the complete, original certificate blob (`bytes`), exactly as
      received on the wire.
    """

    def __init__(self):
        self.key_type = None
        self.nonce = b""
        self.key = None
        self.serial = 0
        self.certificate_type = 0
        self.key_id = ""
        self.principals = []
        self.valid_after = 0
        self.valid_before = 0
        self.critical_options = {}
        self.extensions = {}
        self.signature_key_type = ""
        self.signature = b""
        self.blob = b""
        # Offset of the outer signature string; everything before it is
        # covered by the CA signature.  Populated during parsing.
        self._signed_length = 0
        # The trusted CA key whose signature verified, set by
        # CertificateValidator.validate().
        self.signing_ca = None

    def __repr__(self):
        return (
            "<OpenSSHCertificate type={!r} key_id={!r} principals={!r}>"
        ).format(self.key_type, self.key_id, self.principals)

    def __eq__(self, other):
        return (
            isinstance(other, OpenSSHCertificate)
            and other.blob == self.blob
        )

    def __hash__(self):
        return hash(self.blob)

    @classmethod
    def from_blob(cls, blob):
        """
        Parse a raw certificate blob (the SSH string payload, not including
        any outer length prefix) into an `.OpenSSHCertificate`.

        :raises `.InvalidCertificate`: if the blob is not a well-formed
            version-1 OpenSSH certificate.
        """
        if not isinstance(blob, (bytes, bytearray)):
            raise InvalidCertificate(
                "Certificate blob must be bytes, got {}".format(
                    type(blob).__name__
                )
            )
        blob = bytes(blob)
        message = Message(blob)
        cert = cls()
        cert.blob = blob
        try:
            cert._parse(message)
        except InvalidCertificate:
            raise
        except Exception as e:
            # Any structural surprise (truncation, bad UTF-8, wrong field
            # lengths, ...) means the blob is not a valid certificate.
            raise InvalidCertificate(
                "Malformed certificate: {}".format(e)
            ) from e
        return cert

    def _parse(self, message):
        cert = self
        cert.key_type = message.get_text()
        if cert.key_type not in _CERT_TYPE_PREFIXES:
            raise InvalidCertificate(
                "Not an OpenSSH v01 certificate: {!r}".format(cert.key_type)
            )
        cert.nonce = message.get_binary()
        # The embedded public key section uses the same layout as a standalone
        # public key blob of the underlying type; reuse PKey parsing by
        # rewrapping just that section.
        cert.key = type(cert)._load_inner_key(cert.key_type, message)
        cert.serial = message.get_int64()
        cert.certificate_type = message.get_int()
        allowed_types = (SSH_CERT_TYPE_USER, SSH_CERT_TYPE_HOST)
        if cert.certificate_type not in allowed_types:
            raise InvalidCertificate(
                "Unknown certificate type value {}".format(
                    cert.certificate_type
                )
            )
        cert.key_id = message.get_text()
        cert.principals = _parse_principals(message.get_binary())
        cert.valid_after = message.get_int64()
        cert.valid_before = message.get_int64()
        cert.critical_options = _parse_cert_map(message.get_binary())
        cert.extensions = _parse_cert_map(message.get_binary())
        # Reserved field, must be empty.
        reserved = message.get_binary()
        if reserved:
            raise InvalidCertificate("Non-empty certificate reserved field")
        # Canonical v01 certificates have exactly one outer signature string.
        # Some ssh-keygen builds emit an additional, non-canonical signature
        # field before the real one; parse every trailing string and treat the
        # *last* well-formed one as the CA signature. The final signature
        # covers everything up to the first outer signature string, i.e. the
        # whole blob minus that final outer string and its length prefix.
        cert._extra_signature_blobs = []
        try:
            signature_blob = message.get_binary()
            while message.get_remainder():
                cert._extra_signature_blobs.append(signature_blob)
                signature_blob = message.get_binary()
        except Exception as e:
            raise InvalidCertificate(
                "Malformed certificate signature section: {}".format(e)
            ) from e
        # Every trailing string must start with a known signature algorithm
        # name. The final one additionally has to be a fully-consumed
        # algorithm+value pair; the non-canonical extra fields emitted by
        # some ssh-keygen builds may themselves contain further nested
        # content, but their leading algorithm still has to be recognized,
        # so arbitrary junk appended to a certificate is rejected rather
        # than silently swallowed as a "signature".
        all_candidates = cert._extra_signature_blobs + [signature_blob]
        for index, candidate in enumerate(all_candidates):
            inner = Message(candidate)
            try:
                algorithm = inner.get_text()
                value = inner.get_binary()
            except Exception as e:
                raise InvalidCertificate(
                    "Malformed trailing signature field: {}".format(e)
                ) from e
            if not value or not _is_plausible_signature_algorithm(algorithm):
                raise InvalidCertificate(
                    "Unknown CA signature algorithm {!r}".format(algorithm)
                )
            if index == len(all_candidates) - 1 and inner.get_remainder():
                raise InvalidCertificate(
                    "Malformed trailing signature field"
                )
        cert._signed_length = len(cert.blob) - 4 - len(signature_blob)
        signature_message = Message(signature_blob)
        cert.signature_key_type = signature_message.get_text()
        cert.signature = signature_message.get_binary()
        # The outer message must have been consumed exactly; Message reads
        # pad short input with zero bytes, so a truncated blob would
        # otherwise silently produce a fake signature.
        if message.get_remainder():
            raise InvalidCertificate(
                "Trailing data after certificate signature"
            )

    @classmethod
    def from_public_blob(cls, public_blob):
        """
        Parse a `.PublicBlob` known to hold a certificate.

        :raises `.InvalidCertificate`: if it is not a certificate blob.
        """
        key_type = getattr(public_blob, "key_type", "")
        if not key_type.endswith("-cert-v01@openssh.com"):
            raise InvalidCertificate(
                "PublicBlob {!r} is not a certificate".format(key_type)
            )
        return cls.from_blob(public_blob.key_blob)

    @staticmethod
    def _load_inner_key(cert_key_type, message):
        # Import locally to avoid an import cycle (pkey-ish classes pull in a
        # lot of the package).
        from paramiko import ECDSAKey, Ed25519Key, RSAKey

        if cert_key_type == "ssh-rsa-cert-v01@openssh.com":
            e = message.get_mpint()
            n = message.get_mpint()
            inner = Message()
            inner.add_string("ssh-rsa")
            inner.add_mpint(e)
            inner.add_mpint(n)
            return RSAKey(data=inner.asbytes())
        if cert_key_type.startswith("ecdsa-sha2-"):
            curve = message.get_text()
            point = message.get_binary()
            inner = Message()
            inner.add_string("ecdsa-sha2-{}".format(curve))
            inner.add_string(curve)
            inner.add_string(point)
            return ECDSAKey(data=inner.asbytes())
        if cert_key_type == "ssh-ed25519-cert-v01@openssh.com":
            public_bytes = message.get_binary()
            inner = Message()
            inner.add_string("ssh-ed25519")
            inner.add_string(public_bytes)
            return Ed25519Key(data=inner.asbytes())
        # Unreachable: key_type was checked against _CERT_TYPE_PREFIXES.
        raise InvalidCertificate(
            "Unsupported certificate key type {!r}".format(cert_key_type)
        )

    @property
    def signed_blob(self):
        """
        The bytes covered by the CA's signature.

        Per PROTOCOL.certkeys, the signature is computed over every field up
        to and including the empty ``reserved`` string, i.e. the full blob
        minus the outer signature string (and its 4-byte length prefix).
        """
        return self.blob[: self._signed_length]

    @property
    def signature_message(self):
        """
        A fresh `.Message` containing the embedded CA signature, in the
        layout expected by `.PKey.verify_ssh_sig`.

        A new message (rewound to its start) is returned on every access so
        callers can read it without worrying about the shared stream
        position.
        """
        message = Message()
        message.add_string(self.signature_key_type)
        message.add_string(self.signature)
        # add_string leaves the stream pointer at EOF; rewind so the verifier
        # reads from the start.
        message.rewind()
        return message

    def is_user_certificate(self):
        """Return ``True`` if this is a user (as opposed to host) cert."""
        return self.certificate_type == SSH_CERT_TYPE_USER

    def valid_at(self, timestamp=None):
        """
        Whether the certificate's validity window covers ``timestamp``.

        :param timestamp: UTC Unix timestamp; defaults to the current time.
        """
        if timestamp is None:
            timestamp = int(time.time())
        return self.valid_after <= timestamp < self.valid_before

    def has_principal(self, username):
        """
        Exact, case-sensitive membership of ``username`` in principals.

        An empty principal list means the certificate may be used for any
        user per OpenSSH semantics; callers that want strict behavior should
        configure explicit principals.  This method mirrors the OpenSSH
        check, including the empty-list wildcard.
        """
        if not self.principals:
            return True
        return username in self.principals

    def force_command(self):
        """
        The decoded ``force-command`` critical option, or ``None``.
        """
        if "force-command" not in self.critical_options:
            return None
        return u(Message(self.critical_options["force-command"]).get_binary())

    def source_addresses(self):
        """
        The list of allowed source networks from the ``source-address``
        critical option, or ``None``.

        Entries are returned as `ipaddress` networks (single addresses are
        represented as ``/32`` / ``/128`` networks, as OpenSSH does).
        """
        if "source-address" not in self.critical_options:
            return None
        raw = u(
            Message(self.critical_options["source-address"]).get_binary()
        )
        networks = []
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            networks.append(ipaddress.ip_network(entry, strict=False))
        return networks

    def format_validity(self):
        """Human-readable validity window, useful for logging."""

        def fmt(value):
            if value in (0, 2 ** 64 - 1):
                return "forever" if value else "epoch"
            return datetime.fromtimestamp(
                value, tz=timezone.utc
            ).isoformat()

        return "{} .. {}".format(
            fmt(self.valid_after), fmt(self.valid_before)
        )


_SIGNATURE_ALGORITHMS = frozenset(
    (
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-ed25519",
    )
)


def _is_plausible_signature_algorithm(algorithm):
    return algorithm in _SIGNATURE_ALGORITHMS


def _signature_algorithm_matches_key(algorithm, ca_key):
    """
    Check that an embedded CA signature algorithm is valid for the CA key.

    The signature algorithm must belong to the same key family as the CA key
    itself: an RSA CA may only sign with RSA algorithms, an ECDSA CA only
    with its own curve's ECDSA algorithm, and an Ed25519 CA only with
    ``ssh-ed25519``.
    """
    ca_name = ca_key.get_name()
    if ca_name == "ssh-rsa":
        return algorithm in (
            "ssh-rsa",
            "rsa-sha2-256",
            "rsa-sha2-512",
        )
    if ca_name.startswith("ecdsa-sha2-"):
        return algorithm == ca_name
    if ca_name == "ssh-ed25519":
        return algorithm == "ssh-ed25519"
    return False


class CertificateValidator:
    """
    Server-side validator for OpenSSH user certificates.

    A validator is bound to a collection of trusted CA public keys.  It
    performs, in order, the checks required for safe user authentication:

    1. The blob parses as an OpenSSH v01 certificate.
    2. It is a *user* certificate (host certs are rejected).
    3. It is currently within its validity window.
    4. The requested ``username`` appears exactly in its principal list (or
       the list is empty, matching OpenSSH's wildcard behavior).
    5. All of its critical options are ones the library understands
       (``force-command`` and ``source-address``); unknown options are
       rejected.
    6. It is signed by one of the trusted CAs, using a signature algorithm
       compatible with that CA's key, and the signature verifies.

    Any failure raises a `.CertificateError` subclass; callers in the auth
    path translate that into an authentication failure.

    :param trusted_ca_keys:
        Iterable of trusted CA public keys (`.PKey` objects, typically loaded
        from ``.pub`` files).  May also be a callable taking the requested
        username and returning such an iterable, for per-user CA selection.
    :param now:
        Optional callable returning the current UTC Unix timestamp; defaults
        to :func:`time.time`.  Mainly useful for tests.
    """

    def __init__(self, trusted_ca_keys=(), now=None):
        if callable(trusted_ca_keys) and not hasattr(
            trusted_ca_keys, "verify_ssh_sig"
        ):
            self._ca_provider = trusted_ca_keys
            self._static_cas = ()
        else:
            self._ca_provider = None
            self._static_cas = tuple(trusted_ca_keys)
        self._now = now or time.time

    def trusted_ca_keys(self, username=None):
        """
        Return the trusted CA keys applicable to ``username``.

        When the validator was given a static collection it is returned
        unchanged; otherwise the per-user callable is consulted.
        """
        if self._ca_provider is not None:
            return tuple(self._ca_provider(username))
        return self._static_cas

    def parse(self, blob_or_cert):
        """Parse a blob, or pass through an already-parsed certificate."""
        if isinstance(blob_or_cert, OpenSSHCertificate):
            return blob_or_cert
        return OpenSSHCertificate.from_blob(blob_or_cert)

    def validate(self, blob_or_cert, username):
        """
        Run every trust check and return the parsed `.OpenSSHCertificate`
        on success.

        :raises `.CertificateError`: on any failed check.
        """
        cert = self.parse(blob_or_cert)
        # 2: user certificates only.
        if not cert.is_user_certificate():
            raise InvalidCertificate(
                "Rejecting host certificate (type={}) during user "
                "authentication".format(cert.certificate_type)
            )
        # 3: validity window.
        now = int(self._now())
        if not cert.valid_at(now):
            raise InvalidCertificate(
                "Certificate {} is outside its validity window {} "
                "(now={})".format(cert.key_id, cert.format_validity(), now)
            )
        # 4: principal.
        if not cert.has_principal(username):
            raise InvalidCertificate(
                "Principal {!r} not in certificate principals {}".format(
                    username, cert.principals
                )
            )
        # 5: critical options must all be known.  The actual enforcement of
        # force-command / source-address is the caller's responsibility and
        # the parsed values are handed over verbatim; unknown options cannot
        # be silently ignored.
        unknown = [
            name
            for name in cert.critical_options
            if name not in _KNOWN_CRITICAL_OPTIONS
        ]
        if unknown:
            raise InvalidCertificate(
                "Certificate contains unknown critical options: {}".format(
                    ", ".join(unknown)
                )
            )
        # 6: trusted CA signature with matching algorithm.
        self._verify_signature(cert, username)
        return cert

    def _verify_signature(self, cert, username):
        cas = self.trusted_ca_keys(username)
        if not cas:
            raise UntrustedCertificate(
                "No trusted CA keys are configured for user {!r}".format(
                    username
                )
            )
        signed = cert.signed_blob
        for ca_key in cas:
            if not _signature_algorithm_matches_key(
                cert.signature_key_type, ca_key
            ):
                # A CA whose key type disagrees with the signature algorithm
                # can never validate this blob; keep looking rather than
                # burning the verify on a guaranteed mismatch.
                continue
            try:
                if ca_key.verify_ssh_sig(signed, cert.signature_message):
                    # Remember which CA validated, for the callback's benefit
                    # and for auditing.
                    cert.signing_ca = ca_key
                    return
            except Exception:
                # A malformed signature or an unsupported algorithm on one
                # candidate CA must not abort the whole search.
                continue
        raise UntrustedCertificate(
            "Certificate {} signature did not verify against any trusted "
            "CA (signature algorithm {!r})".format(
                cert.key_id, cert.signature_key_type
            )
        )

    def check_source_address(self, cert, peer_address):
        """
        Evaluate a ``source-address`` critical option against a peer address.

        This is a helper for callers that choose to enforce the option
        themselves (Paramiko does not intercept channel semantics, so per the
        contract the parsed option is always exposed via
        `.OpenSSHCertificate.source_addresses`).  Returns ``True`` when the
        certificate carries no such option, or when ``peer_address`` falls in
        one of the allowed networks.

        :param str peer_address:
            The client's IP address, e.g. from `.Transport.getpeername`.
        """
        networks = cert.source_addresses()
        if networks is None:
            return True
        try:
            address = ipaddress.ip_address(peer_address)
        except ValueError:
            return False
        return any(address in network for network in networks)
