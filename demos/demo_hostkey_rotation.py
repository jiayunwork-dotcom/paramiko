#!/usr/bin/env python3
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
Terminal demo: surviving an SSH host-key rotation with host-key learning.

A server rotating its host key goes through an overlap period where the
old key is still trusted by clients but the new key is not yet known to
them.  This demo shows how `SSHClient.learn_host_keys` (the OpenSSH
``hostkeys-00@openssh.com`` / ``hostkeys-prove-00@openssh.com``
extensions, a.k.a. ``UpdateHostKeys``) lets a client pick up the new key
over the still-trusted old connection:

    1. the client only trusts the server's OLD key (known_hosts);
    2. connecting to the server while it presents its NEW key fails;
    3. over a connection anchored in the OLD key, the server announces
       all of its keys and proves possession of the private halves --
       the client learns the new keys into its known_hosts;
    4. the next connection to the NEW-key-presenting server succeeds,
       and the OLD key keeps working too during the overlap.

Run:  python3 demo_hostkey_rotation.py
"""

import os
import socket
import sys
import tempfile
import threading
import time

# Allow running both as "python3 demos/demo_hostkey_rotation.py" and as
# "python3 demo_hostkey_rotation.py" from inside demos/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paramiko  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# The server's key material, reusing the repository's demo keys:
#   OLD      - the key clients already trust (demos/test_rsa.key)
#   NEW_RSA  - the replacement key, same algorithm (demos/user_rsa_key)
#   NEW_EC   - an additional new key of another algorithm (generated)
OLD = paramiko.RSAKey.from_private_key_file(os.path.join(HERE, "test_rsa.key"))
NEW_RSA = paramiko.RSAKey.from_private_key_file(
    os.path.join(HERE, "user_rsa_key")
)
NEW_EC = paramiko.ECDSAKey.generate()
NEW_KEYS = [NEW_RSA, NEW_EC]
ALL_KEYS = [OLD] + NEW_KEYS

USERNAME, PASSWORD = "demo", "secret"


def fingerprint(key):
    return "{} {}".format(key.get_name(), key.get_fingerprint().hex())


class RotationServer(paramiko.ServerInterface):
    """
    Minimal OpenSSH-like server: announces its host keys after user
    authentication and proves possession of the private halves.
    """

    def __init__(self, transport, prove_keys):
        self.transport = transport
        self.private_keys = {k.asbytes(): k for k in prove_keys}

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        if (username, password) == (USERNAME, PASSWORD):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_global_request(self, kind, msg):
        if kind != "hostkeys-prove-00@openssh.com":
            return False
        signatures = []
        while len(msg.get_remainder()) > 0:
            blob = msg.get_string()
            key = self.private_keys.get(blob)
            if key is None:
                return False
            # The proof binds the extension name, this connection's
            # session ID, and the announced public key.
            proof = paramiko.Message()
            proof.add_string("hostkeys-prove-00@openssh.com")
            proof.add_string(self.transport.session_id)
            proof.add_string(blob)
            signatures.append(bytes(key.sign_ssh_data(bytes(proof))))
        return tuple(signatures)


def serve_once(listener, handshake_keys, prove_keys):
    """
    Accept one connection on ``listener`` and serve it: handshake with
    ``handshake_keys``, then announce and prove ``prove_keys``.
    """
    conn, _ = listener.accept()
    transport = paramiko.Transport(conn)
    for key in handshake_keys:
        transport.add_server_key(key)
    server = RotationServer(transport, prove_keys)
    transport.start_server(server=server)
    deadline = time.time() + 10
    while (
        not transport.is_authenticated()
        and transport.is_active()
        and time.time() < deadline
    ):
        time.sleep(0.05)
    if transport.is_authenticated() and prove_keys:
        blobs = tuple(k.asbytes() for k in prove_keys)
        transport.global_request("hostkeys-00@openssh.com", blobs, wait=False)
    while transport.is_active():
        time.sleep(0.1)
    transport.close()


def start_server(listener, handshake_keys, prove_keys):
    thread = threading.Thread(
        target=serve_once,
        args=(listener, handshake_keys, prove_keys),
        daemon=True,
    )
    thread.start()
    return thread


def make_client(known_hosts):
    client = paramiko.SSHClient()
    # RejectPolicy: nothing is ever accepted on first use here -- the
    # only way in is via keys already in known_hosts.
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.load_host_keys(known_hosts)
    return client


def connect(client, port):
    client.connect(
        "127.0.0.1",
        port=port,
        username=USERNAME,
        password=PASSWORD,
        look_for_keys=False,
        allow_agent=False,
    )


def wait_for_announcement(client, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        announced = client.get_transport().get_announced_host_keys()
        if announced:
            return announced
        time.sleep(0.05)
    raise SystemExit("server never announced its host keys")


def show_known_hosts(path):
    print("    --- known_hosts ---")
    with open(path) as f:
        for line in f:
            name, keytype, blob = line.split()
            print("    {} {} {}...".format(name, keytype, blob[:24]))
    print("    -------------------")


def main():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]
    name = "[127.0.0.1]:{}".format(port)

    tmpdir = tempfile.mkdtemp(prefix="paramiko-rotation-demo-")
    known_hosts = os.path.join(tmpdir, "known_hosts")
    with open(known_hosts, "w") as f:
        f.write("{} {} {}\n".format(name, OLD.get_name(), OLD.get_base64()))

    print("Server is rotating its host key.")
    print("  old (trusted):  {}".format(fingerprint(OLD)))
    for key in NEW_KEYS:
        print("  new (unknown):  {}".format(fingerprint(key)))
    print("\nClient known_hosts trusts only the old key:")
    show_known_hosts(known_hosts)

    print("\n[1] Connecting to the server presenting its NEW key...")
    start_server(listener, [NEW_RSA], [])
    client = make_client(known_hosts)
    try:
        connect(client, port)
        print("    unexpected success -- this should not happen!")
        return 1
    except paramiko.ssh_exception.BadHostKeyException:
        print("    rejected with BadHostKeyException, as expected.")
    finally:
        client.close()

    print("\n[2] Connecting to the server presenting its OLD key...")
    start_server(listener, [OLD], ALL_KEYS)
    client = make_client(known_hosts)
    connect(client, port)
    print("    connected (handshake key trusted via known_hosts).")
    announced = wait_for_announcement(client)
    print(
        "    server announced {} host key(s); asking for proofs...".format(
            len(announced)
        )
    )
    learned = client.learn_host_keys()
    for key in learned:
        print("    learned: {}".format(fingerprint(key)))
    client.close()
    print("\n    known_hosts after learning (old key kept, new added):")
    show_known_hosts(known_hosts)

    print("\n[3] Reconnecting to the server presenting its NEW key...")
    start_server(listener, [NEW_RSA], [])
    client = make_client(known_hosts)
    connect(client, port)
    remote = client.get_transport().get_remote_server_key()
    print(
        "    success -- {} accepted via learned keys.".format(
            fingerprint(remote)
        )
    )
    client.close()

    print("\n[4] The OLD key still works during the overlap period...")
    start_server(listener, [OLD], [])
    client = make_client(known_hosts)
    connect(client, port)
    print("    success -- old key remains trusted.")
    client.close()

    listener.close()
    print("\nRotation complete: both keys trusted, no first-use prompts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
