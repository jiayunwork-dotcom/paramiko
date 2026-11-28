# Server-side OpenSSH user certificate support — API changes & migration

## Why this change

Paramiko could already *offer* OpenSSH certificates as a client
(`PKey.load_certificate`), but a server only ever saw the certificate as an
unparsed blob wrapped around the underlying public key. Nothing verified the
CA signature, principals, validity period or critical options, so
certificate users had to fall back to enumerating every user's bare public
key.

This change adds full server-side validation of
`*-cert-v01@openssh.com` user certificates.

## New public API

All new names are exported from the top-level `paramiko` package and live in
`paramiko/certificate.py`:

- `OpenSSHCertificate` — parsed view of a certificate (principals, validity,
  critical options, extensions, embedded CA signature, the signing CA after
  validation). Constructed via `OpenSSHCertificate.from_blob(bytes)` or
  `OpenSSHCertificate.from_public_blob(PublicBlob)`.
- `CertificateValidator(trusted_ca_keys, now=None)` — runs the trust checks.
  `trusted_ca_keys` is either an iterable of trusted CA public keys
  (`PKey`), or a callable `username -> iterable of CA keys` for per-user CA
  selection. `now` is an injectable clock (defaults to `time.time`).
- Exceptions: `CertificateError` (base, an `SSHException` subclass),
  `InvalidCertificate` (malformed/host cert/expired/wrong principal/unknown
  critical option), `UntrustedCertificate` (no matching trusted CA or bad
  signature).

`Transport` gains two methods:

- `Transport.set_certificate_validator(validator)` — install a configured
  validator.
- `Transport.add_trusted_ca_key(ca_key)` — convenience; creates a default
  validator on first call and accumulates trusted CA keys.

`PKey` gains a `certificate` attribute: `None` for plain keys and client
keys; for a server-side key object passed to
`ServerInterface.check_auth_publickey`, it holds the exact
`OpenSSHCertificate` instance the library validated (never a second,
independently re-interpreted parse of the blob).

## What the library guarantees before your callback runs

For a certificate-bearing request, in order:

1. the blob parses as an OpenSSH v01 **user** certificate (host
   certificates are rejected);
2. the current time is inside `valid_after .. valid_before`;
3. the requested username is an exact, case-sensitive member of
   `principals` (an empty principal list is the OpenSSH wildcard);
4. every critical option is recognized — only `force-command` and
   `source-address`; unknown options reject the certificate;
5. the CA signature verifies against a trusted CA key using an algorithm of
   the same key family (RSA CA → RSA algos, ECDSA CA → its curve's algo,
   Ed25519 CA → `ssh-ed25519`).

Only then is `check_auth_publickey` called, with `key.certificate`
populated. After the callback accepts, Paramiko still verifies the client's
signature proving possession of the matching private key — certificate
validation never replaces proof of possession.

## Critical options

Paramiko does not intercept channel/session semantics, so it does not
execute `force-command` or network-filter `source-address` itself. Instead
the parsed values are always exposed on the validated certificate and your
callback is responsible for honoring them before returning
`AUTH_SUCCESSFUL`:

- `cert.force_command() -> str | None`
- `cert.source_addresses() -> list[ipaddress._BaseNetwork] | None`
- helper: `CertificateValidator.check_source_address(cert, peer_ip) -> bool`

Unknown critical options are rejected at validation time, so a callback can
never accept a certificate carrying an option it never saw.

## Migration

### New servers (recommended)

```python
from paramiko import Transport, ServerInterface, Ed25519Key, AUTH_SUCCESSFUL
from paramiko.certificate import CertificateValidator

ca_public = Ed25519Key(data=...)            # load from your ca.pub
validator = CertificateValidator([ca_public])
transport.set_certificate_validator(validator)

class Server(ServerInterface):
    def check_auth_publickey(self, username, key):
        if key.certificate is not None:
            # Fully validated already; apply your own policy on the parsed
            # certificate, including critical options.
            return AUTH_SUCCESSFUL
        # Existing bare-key logic, unchanged.
        return AUTH_FAILED if key not in allowed_bare_keys else AUTH_SUCCESSFUL
```

### Existing servers that currently accept certificate blobs as bare keys

Previously a certificate arrived as a key object whose `get_name()` was the
underlying key type (e.g. `ssh-rsa`), so any allowlist/fingerprint check
could accept it. That path is now closed:

- if **no validator is configured**, every certificate request fails
  authentication and `check_auth_publickey` is not invoked for it;
- bare public keys behave exactly as before, so existing non-certificate
  users are unaffected;
- the two paths never cross-subsidize: a rejected certificate cannot fall
  back to an accepted bare key under the same username.

To re-enable certificate users, configure the trusted CA(s) as above and
handle `key.certificate` in your callback. Short-lived certificates signed
by that CA then work without per-user key entries.

## Test fixtures

All fixtures used by the test suite are generated offline with
`ssh-keygen` and stored under `tests/_support/certs/` (CA keys, user keys,
and certificates covering valid/expired/future/wrong-principal/host/
untrusted-CA/unknown-critical-option/force-command/source-address cases).
No external CA or real SSH server is required; integration tests connect a
client and server `Transport` over an in-process loopback socket.
