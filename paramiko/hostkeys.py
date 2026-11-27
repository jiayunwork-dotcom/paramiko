# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.


from base64 import encodebytes, decodebytes
import binascii
import os
import re
import stat
import tempfile
import threading

from collections.abc import MutableMapping
from contextlib import contextmanager
from hashlib import sha1
from hmac import HMAC

try:
    import fcntl
except ImportError:
    fcntl = None
try:
    import msvcrt
except ImportError:
    msvcrt = None


from paramiko.pkey import PKey, UnknownKeyType
from paramiko.util import get_logger, constant_time_bytes_eq, b, u
from paramiko.ssh_exception import SSHException


class HostKeys(MutableMapping):
    """
    Representation of an OpenSSH-style "known hosts" file.  Host keys can be
    read from one or more files, and then individual hosts can be looked up to
    verify server keys during SSH negotiation.

    A `.HostKeys` object can be treated like a dict; any dict lookup is
    equivalent to calling `lookup`.

    .. versionadded:: 1.5.3
    """

    def __init__(self, filename=None):
        """
        Create a new HostKeys object, optionally loading keys from an OpenSSH
        style host-key file.

        :param str filename: filename to load host keys from, or ``None``
        """
        # emulate a dict of { hostname: { keytype: PKey } }
        self._entries = []
        if filename is not None:
            self.load(filename)

    def add(self, hostname, keytype, key):
        """
        Add a host key entry to the table.  Any existing entry for a
        ``(hostname, keytype)`` pair will be replaced.

        :param str hostname: the hostname (or IP) to add
        :param str keytype: key type (``"ssh-rsa"`` or ``"ssh-dss"``)
        :param .PKey key: the key to add
        """
        for e in self._entries:
            if (hostname in e.hostnames) and (e.key.get_name() == keytype):
                e.key = key
                return
        self._entries.append(HostKeyEntry([hostname], key))

    def load(self, filename):
        """
        Read a file of known SSH host keys, in the format used by OpenSSH.
        This type of file unfortunately doesn't exist on Windows, but on
        posix, it will usually be stored in
        ``os.path.expanduser("~/.ssh/known_hosts")``.

        If this method is called multiple times, the host keys are merged,
        not cleared.  So multiple calls to `load` will just call `add`,
        replacing any existing entries and adding new ones.

        :param str filename: name of the file to read host keys from

        :raises: ``IOError`` -- if there was an error reading the file
        """
        with open(filename, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if (len(line) == 0) or (line[0] == "#"):
                    continue
                try:
                    entry = HostKeyEntry.from_line(line, lineno)
                except SSHException:
                    continue
                if entry is not None:
                    _hostnames = entry.hostnames
                    for h in _hostnames:
                        if self.check(h, entry.key):
                            entry.hostnames.remove(h)
                    if len(entry.hostnames):
                        self._entries.append(entry)

    def save(self, filename):
        """
        Save host keys into a file, in the format used by OpenSSH.  The order
        of keys in the file will be preserved when possible (if these keys were
        loaded from a file originally).  The single exception is that combined
        lines will be split into individual key lines, which is arguably a bug.

        :param str filename: name of the file to write

        :raises: ``IOError`` -- if there was an error writing the file

        .. versionadded:: 1.6.1
        """
        with open(filename, "w") as f:
            for e in self._entries:
                line = e.to_line()
                if line:
                    f.write(line)

    def lookup(self, hostname):
        """
        Find a hostkey entry for a given hostname or IP.  If no entry is found,
        ``None`` is returned.  Otherwise a dictionary of keytype to key is
        returned.  The keytype will be either ``"ssh-rsa"`` or ``"ssh-dss"``.

        :param str hostname: the hostname (or IP) to lookup
        :return: dict of `str` -> `.PKey` keys associated with this host
            (or ``None``)
        """

        class SubDict(MutableMapping):
            def __init__(self, hostname, entries, hostkeys):
                self._hostname = hostname
                self._entries = entries
                self._hostkeys = hostkeys

            def __iter__(self):
                for k in self.keys():
                    yield k

            def __len__(self):
                return len(self.keys())

            def __delitem__(self, key):
                for e in list(self._entries):
                    if e.key.get_name() == key:
                        self._entries.remove(e)
                        break
                else:
                    raise KeyError(key)

            def __getitem__(self, key):
                for e in self._entries:
                    if e.key.get_name() == key:
                        return e.key
                raise KeyError(key)

            def __setitem__(self, key, val):
                for e in self._entries:
                    if e.key is None:
                        continue
                    if e.key.get_name() == key:
                        # replace
                        e.key = val
                        break
                else:
                    # add a new one
                    e = HostKeyEntry([hostname], val)
                    self._entries.append(e)
                    self._hostkeys._entries.append(e)

            def keys(self):
                return [
                    e.key.get_name()
                    for e in self._entries
                    if e.key is not None
                ]

        entries = []
        for e in self._entries:
            if self._hostname_matches(hostname, e):
                entries.append(e)
        if len(entries) == 0:
            return None
        return SubDict(hostname, entries, self)

    def _hostname_matches(self, hostname, entry):
        """
        Tests whether ``hostname`` string matches given SubDict ``entry``.

        :returns bool:
        """
        for h in entry.hostnames:
            if (
                h == hostname
                or h.startswith("|1|")
                and not hostname.startswith("|1|")
                and constant_time_bytes_eq(self.hash_host(hostname, h), h)
            ):
                return True
        return False

    def check(self, hostname, key):
        """
        Return True if the given key is associated with the given hostname
        in this dictionary.

        Any matching entry counts: a host may legitimately have several
        keys of the same type trusted at once, e.g. the old and new key
        of a server that is rotating its host key, so this returns
        ``True`` if *any* entry for the host holds exactly this key.

        :param str hostname: hostname (or IP) of the SSH server
        :param .PKey key: the key to check
        :return:
            ``True`` if the key is associated with the hostname; else ``False``
        """
        for e in self._entries:
            if e.key is None:
                continue
            if not self._hostname_matches(hostname, e):
                continue
            if e.key.get_name() != key.get_name():
                continue
            if e.key.asbytes() == key.asbytes():
                return True
        return False

    def add_if_absent(self, hostname, key, storage_name=None):
        """
        Add a host key entry for ``hostname`` unless this exact key is
        already trusted for that host.  Unlike `add`, this never
        replaces an existing entry, so old and new keys of the same key
        type remain trusted side by side (as needed during a host-key
        rotation overlap).

        :param str hostname:
            the cleartext hostname (or IP), used to find existing
            entries for de-duplication
        :param .PKey key: the key to add
        :param str storage_name:
            the name written into the new entry; defaults to
            ``hostname``.  Pass ``HostKeys.hash_host(hostname)`` to
            store a hashed name when the rest of the user's file uses
            hashed hostnames.
        :return: ``True`` if a new entry was added, ``False`` if the
            key was already present

        .. versionadded:: 3.6
        """
        if self.check(hostname, key):
            return False
        self._entries.append(HostKeyEntry([storage_name or hostname], key))
        return True

    def matching_entry(self, hostname, key):
        """
        Return the first `.HostKeyEntry` that trusts ``key`` for
        ``hostname`` -- i.e. the entry that would authenticate this
        host/key pair -- or ``None`` if there is no such entry.

        :param str hostname: hostname (or IP) of the SSH server
        :param .PKey key: the key to look up
        :return: a `.HostKeyEntry` or ``None``

        .. versionadded:: 3.6
        """
        for e in self._entries:
            if e.key is None:
                continue
            if not self._hostname_matches(hostname, e):
                continue
            if e.key.asbytes() == key.asbytes():
                return e
        return None

    def clear(self):
        """
        Remove all host keys from the dictionary.
        """
        self._entries = []

    def __iter__(self):
        for k in self.keys():
            yield k

    def __len__(self):
        return len(self.keys())

    def __getitem__(self, key):
        ret = self.lookup(key)
        if ret is None:
            raise KeyError(key)
        return ret

    def __delitem__(self, key):
        index = None
        for i, entry in enumerate(self._entries):
            if self._hostname_matches(key, entry):
                index = i
                break
        if index is None:
            raise KeyError(key)
        self._entries.pop(index)

    def __setitem__(self, hostname, entry):
        # don't use this please.
        if len(entry) == 0:
            self._entries.append(HostKeyEntry([hostname], None))
            return
        for key_type in entry.keys():
            found = False
            for e in self._entries:
                if (hostname in e.hostnames) and e.key.get_name() == key_type:
                    # replace
                    e.key = entry[key_type]
                    found = True
            if not found:
                self._entries.append(HostKeyEntry([hostname], entry[key_type]))

    def keys(self):
        ret = []
        for e in self._entries:
            for h in e.hostnames:
                if h not in ret:
                    ret.append(h)
        return ret

    def values(self):
        ret = []
        for k in self.keys():
            ret.append(self.lookup(k))
        return ret

    @staticmethod
    def hash_host(hostname, salt=None):
        """
        Return a "hashed" form of the hostname, as used by OpenSSH when storing
        hashed hostnames in the known_hosts file.

        :param str hostname: the hostname to hash
        :param str salt: optional salt to use when hashing
            (must be 20 bytes long)
        :return: the hashed hostname as a `str`
        """
        if salt is None:
            salt = os.urandom(sha1().digest_size)
        else:
            if salt.startswith("|1|"):
                salt = salt.split("|")[2]
            salt = decodebytes(b(salt))
        assert len(salt) == sha1().digest_size
        hmac = HMAC(salt, b(hostname), sha1).digest()
        hostkey = "|1|{}|{}".format(u(encodebytes(salt)), u(encodebytes(hmac)))
        return hostkey.replace("\n", "")


class InvalidHostKey(Exception):
    def __init__(self, line, exc):
        self.line = line
        self.exc = exc
        self.args = (line, exc)


class HostKeyEntry:
    """
    Representation of a line in an OpenSSH-style "known hosts" file.
    """

    def __init__(self, hostnames=None, key=None):
        self.valid = (hostnames is not None) and (key is not None)
        self.hostnames = hostnames
        self.key = key

    @classmethod
    def from_line(cls, line, lineno=None):
        """
        Parses the given line of text to find the names for the host,
        the type of key, and the key data. The line is expected to be in the
        format used by the OpenSSH known_hosts file. Fields are separated by a
        single space or tab.

        Lines are expected to not have leading or trailing whitespace.
        We don't bother to check for comments or empty lines.  All of
        that should be taken care of before sending the line to us.

        :param str line: a line from an OpenSSH known_hosts file
        """
        log = get_logger("paramiko.hostkeys")
        fields = re.split(" |\t", line)
        if len(fields) < 3:
            # Bad number of fields
            msg = "Not enough fields found in known_hosts in line {} ({!r})"
            log.info(msg.format(lineno, line))
            return None
        fields = fields[:3]

        names, key_type, key = fields
        names = names.split(",")

        # Decide what kind of key we're looking at and create an object
        # to hold it accordingly.
        try:
            # TODO: this grew organically and doesn't seem /wrong/ per se (file
            # read -> unicode str -> bytes for base64 decode -> decoded bytes);
            # but in Python 3 forever land, can we simply use
            # `base64.b64decode(str-from-file)` here?
            key_bytes = decodebytes(b(key))
        except binascii.Error as e:
            raise InvalidHostKey(line, e)

        try:
            return cls(names, PKey.from_type_string(key_type, key_bytes))
        except UnknownKeyType:
            # TODO 4.0: consider changing HostKeys API so this just raises
            # naturally and the exception is muted higher up in the stack?
            log.info("Unable to handle key of type {}".format(key_type))
            return None

    def to_line(self):
        """
        Returns a string in OpenSSH known_hosts file format, or None if
        the object is not in a valid state.  A trailing newline is
        included.
        """
        if self.valid:
            return "{} {} {}\n".format(
                ",".join(self.hostnames),
                self.key.get_name(),
                self.key.get_base64(),
            )
        return None

    def __repr__(self):
        return "<HostKeyEntry {!r}: {!r}>".format(self.hostnames, self.key)


# ---------------------------------------------------------------------
# Atomic, merge-based updates of known_hosts files
#
# The trusted set is represented as the on-disk known_hosts file plus
# the in-memory `.HostKeys` a client publishes to its handshake check.
# New keys only become trusted (published to memory) after they have
# been committed to disk, so anything the connection check accepts is
# always also present in the file.
#
# Commits are read-modify-write cycles of the form: lock -> re-read the
# current file -> merge (append only what is genuinely new) ->
# atomically replace.  The lock is only held for this short critical
# section, never across the network round trip of a host-key proof; the
# re-read at commit time is what makes that safe, because keys another
# client committed while we were proving are simply found already
# present and skipped.  Merging is additive-only, so a later committer
# can never overwrite an earlier committer's increments, whether they
# concern the same host or unrelated hosts.
# ---------------------------------------------------------------------

# Process-local locks keyed by absolute path, serializing learners
# living in the same process (the advisory file lock below covers other
# processes).
_known_hosts_locks = {}
_known_hosts_locks_guard = threading.Lock()


def _process_lock_for(filename):
    key = os.path.abspath(filename)
    with _known_hosts_locks_guard:
        lock = _known_hosts_locks.get(key)
        if lock is None:
            lock = _known_hosts_locks[key] = threading.Lock()
        return lock


@contextmanager
def _advisory_file_lock(filename):
    """
    Cross-process advisory lock guarding read-modify-write cycles on
    ``filename``.  A stable sidecar (``<filename>.lock``) is used so
    that atomically replacing the data file does not swap the inode
    waiters are queued on.  Degrades to a no-op on platforms without
    ``fcntl``/``msvcrt`` (the process-local lock still applies).
    """
    fd = os.open(filename + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        elif msvcrt is not None:
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        yield
    finally:
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            elif msvcrt is not None:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            os.close(fd)


def _parse_known_hosts(data):
    """
    Build a `.HostKeys` from raw known_hosts file bytes, skipping
    comments and unparseable lines exactly like `.HostKeys.load` does.
    """
    hostkeys = HostKeys()
    text = data.decode("utf-8", "replace")
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if (len(line) == 0) or (line[0] == "#"):
            continue
        try:
            entry = HostKeyEntry.from_line(line, lineno)
        except SSHException:
            continue
        if entry is not None:
            hostkeys._entries.append(entry)
    return hostkeys


def _atomic_append(filename, current, new_lines):
    """
    Write ``current`` plus ``new_lines`` to ``filename`` atomically:
    render to a temp file in the same directory, fsync, then
    ``os.replace``.  On any failure the temp file is removed and the
    original file (and its bytes) is left untouched.
    """
    directory = os.path.dirname(os.path.abspath(filename))
    fd, tmp = tempfile.mkstemp(prefix=".known_hosts-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(current)
            if current and not current.endswith(b"\n"):
                f.write(b"\n")
            for line in new_lines:
                f.write(line.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        try:
            mode = stat.S_IMODE(os.stat(filename).st_mode)
        except OSError:
            # New file: keep it private like the rest of ~/.ssh.
            mode = 0o600
        os.chmod(tmp, mode)
        os.replace(tmp, filename)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def update_known_hosts_file(filename, additions):
    """
    Atomically merge newly learned host keys into a known_hosts file.

    The file is re-read under an advisory lock at commit time, and each
    addition is re-checked against what is on disk *now*: keys that are
    already present (e.g. committed by another client while we were
    verifying proofs) are skipped, so repeated announcements never
    create duplicate entries.  Existing file content is preserved byte
    for byte -- comments, other hosts, and combined multi-host lines
    included -- and genuinely new keys are appended as individual
    single-host lines, so other hosts on a combined line never gain the
    new keys.

    :param str filename: path of the known_hosts file to update
    :param additions:
        an iterable of ``(hostname, storage_name, key)`` tuples, where
        ``hostname`` is the cleartext host name used for
        de-duplication, ``storage_name`` is the name written to the
        file (which may be a hashed ``|1|...`` name), and ``key`` is a
        `.PKey`
    :return:
        the list of ``(storage_name, key)`` pairs actually appended
        (empty when everything was already present)
    :raises: ``IOError`` --
        if the updated file could not be written; the original file is
        left unmodified in that case

    .. versionadded:: 3.6
    """
    additions = list(additions)
    if not additions:
        return []
    lock = _process_lock_for(filename)
    with lock, _advisory_file_lock(filename):
        try:
            with open(filename, "rb") as f:
                current = f.read()
        except FileNotFoundError:
            current = b""
        # Re-verify against the committed trusted set: another learner
        # may have committed some of these keys since our proofs were
        # checked.
        committed = _parse_known_hosts(current)
        fresh = []
        for hostname, storage_name, key in additions:
            if not committed.check(hostname, key):
                fresh.append((storage_name, key))
        if not fresh:
            return []
        new_lines = [
            "{} {} {}\n".format(storage_name, key.get_name(), key.get_base64())
            for storage_name, key in fresh
        ]
        _atomic_append(filename, current, new_lines)
        return fresh
