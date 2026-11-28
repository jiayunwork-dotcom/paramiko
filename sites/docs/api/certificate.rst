========================
Certificate verification
========================

.. versionadded:: 5.2

Paramiko has long been able to *offer* OpenSSH user certificates on the
client side (see `.PKey.load_certificate`), but servers previously only saw
the certificate as an opaque blob wrapped around the underlying public key:
nothing checked the CA signature, principals or validity period, so the only
practical option was to enumerate every user's bare public key.

The :mod:`paramiko.certificate` module adds full, standards-oriented
server-side validation. When a client presents a
``*-cert-v01@openssh.com`` key, Paramiko now verifies -- *before* invoking
any application callback -- that:

- it is a **user** certificate (host certificates are rejected);
- it is signed by a **trusted CA**, using a signature algorithm compatible
  with that CA's key type;
- it is currently **within its validity window**;
- the requested **username is an exact principal** in the certificate;
- it carries **no unknown critical options** (``force-command`` and
  ``source-address`` are recognized and exposed).

A certificate that fails any of these is an authentication failure and is
never handed to the bare public-key callback. After those checks pass,
Paramiko still verifies the client's signature proving possession of the
matching private key, exactly as for a plain key.

Quick start
===========

Build a trust store from your offline CA public keys and attach a
`.CertificateValidator` to the server-mode `.Transport` (or use
`.Transport.add_trusted_ca_key` for the one-liner form)::

    from paramiko import Transport, Ed25519Key
    from paramiko.certificate import CertificateValidator

    ca = Ed25519Key(data=open("ca.pub", "rb").read())  # or from a .pub file
    transport.set_certificate_validator(CertificateValidator([ca]))
    # equivalent: transport.add_trusted_ca_key(ca)

In `.ServerInterface.check_auth_publickey`, a validated certificate is
available on the key itself, as the very same parsed object the library
checked::

    validator = CertificateValidator([ca])
    transport.set_certificate_validator(validator)

    def check_auth_publickey(self, username, key):
        if key.certificate is not None:
            # CA signature, principal and validity already verified here.
            if key.certificate.force_command() is not None:
                ...  # your code must honor it, or reject
            if key.certificate.source_addresses() is not None:
                allowed = validator.check_source_address(
                    key.certificate, transport.getpeername()[0]
                )
                if not allowed:
                    return AUTH_FAILED
            return AUTH_SUCCESSFUL
        # plain keys keep their original behavior
        return AUTH_FAILED

Per-user CA selection is supported by passing a callable (it receives the
requested username and returns the applicable CA keys)::

    validator = CertificateValidator(lambda username: cas_for(username))

Behavior and compatibility
==========================

- Without a configured validator, certificate requests are **rejected**
  rather than treated as bare keys; unvalidated certificates can no longer
  slip through.
- Plain (non-certificate) public keys are completely unaffected and keep
  using the original callback.
- The two paths never fall back into each other: a failed certificate
  cannot be rescued because the same username also has an accepted bare key,
  and vice versa.
- Critical options are never silently ignored. Paramiko does not itself
  intercept channels to enforce ``force-command`` or ``source-address``, so
  their parsed values (plus principals, validity and the signing CA) are
  handed to the callback on `.OpenSSHCertificate`; accepting a certificate
  that carries them means your code is responsible for enforcing them.

API
===

.. automodule:: paramiko.certificate
    :member-order: bysource
