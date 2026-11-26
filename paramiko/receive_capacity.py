# Copyright (C) 2026 ...
# This file is part of Paramiko; licensed under the GNU Lesser General
# Public License, version 2.1 or later.

"""
Connection-level shared receive capacity accounting.

A :class:`ReceiveCapacity` object owns one byte budget for every channel on a
:class:`~paramiko.transport.Transport`.  For each channel it tracks:

* ``window``: receive-window credits already advertised to the peer but not
  yet consumed by an incoming payload;
* ``buffered``: payload bytes currently sitting in the channel's stdout/stderr
  :class:`~paramiko.buffered_pipe.BufferedPipe` objects; and
* ``pending_adjust``: bytes which were read by the application and are
  earmarked for the next window adjustment.  These are *not* part of the
  externally observable occupancy, but keeping them allocated prevents new
  channels or open races from stealing the credits needed to make a
  continuously reading channel progress.

The public occupancy is therefore ``window + buffered`` for every account and
is always at most the configured connection budget.
"""

from __future__ import annotations

import operator
import threading
import weakref
from typing import Dict

from paramiko.ssh_exception import ChannelException, SSHException


# The constructor contract deliberately uses 64 KiB as its smallest accepted
# connection budget.  This is also the default initial window quantum used by
# capacity-managed channels, so a minimum-sized Transport can always open one
# useful channel.
MIN_RECEIVE_CAPACITY = 65536
DEFAULT_INITIAL_WINDOW_QUANTUM = 65536

# Paramiko's long-standing sanitized minimum channel window.  An explicit
# caller request may be that small even when the shared quantum is larger.
MIN_LEGAL_CHANNEL_WINDOW = 32768
OPEN_FAILED_RESOURCE_SHORTAGE = 4


class ReceiveCapacityError(ChannelException):
    """A channel could not reserve enough shared receive capacity."""

    def __init__(self, message):
        super().__init__(OPEN_FAILED_RESOURCE_SHORTAGE, message)
        self.message = message

    def __str__(self):
        return self.message


class ChannelWindowOverflow(SSHException):
    """A peer sent more payload than the channel's advertised window."""

    def __init__(self, chanid, length, window):
        self.chanid = chanid
        self.length = length
        self.window = window
        super().__init__(
            "Channel {} received {} bytes with only {} window bytes".format(
                chanid, length, window
            )
        )


class _ChannelBudget:
    __slots__ = (
        "window",
        "buffered",
        "pending_adjust",
        "revoked",
        "grace_window",
        "channel_ref",
    )

    def __init__(self, window, channel=None):
        self.window = int(window)
        self.buffered = 0
        self.pending_adjust = 0
        self.revoked = False
        # Credits which were valid before a local EOF/close and may still have
        # packets in flight.  Such packets are discarded rather than buffered;
        # the grace value therefore does not participate in the global budget.
        self.grace_window = 0
        self.channel_ref = None if channel is None else weakref.ref(channel)


class ReceiveCapacity:
    """
    A fixed shared byte budget and synchronized per-channel accounts.

    All mutating operations are constant-time and never block waiting for the
    application to read.  The Transport receive thread can therefore call
    :meth:`admit` without stalling other channels.
    """

    def __init__(self, limit):
        if isinstance(limit, bool):
            raise ValueError(
                "receive_capacity must be an int, not {!r}".format(limit)
            )
        try:
            limit = operator.index(limit)
        except TypeError:
            raise ValueError(
                "receive_capacity must be an int, not {!r}".format(limit)
            ) from None
        if limit < MIN_RECEIVE_CAPACITY:
            raise ValueError(
                "receive_capacity must be at least {} bytes".format(
                    MIN_RECEIVE_CAPACITY
                )
            )
        self.limit = limit
        self._lock = threading.RLock()
        self._channels: Dict[int, _ChannelBudget] = {}
        # Exact externally visible occupancy: window + buffered.
        self.occupied = 0
        # Occupancy plus read bytes earmarked for future window adjustments.
        # This is the value new channel reservations must fit within.
        self.allocated = 0

    # -- simple introspection -------------------------------------------------

    @property
    def used(self):
        """Current exact occupancy in bytes."""
        with self._lock:
            return self.occupied

    @property
    def available(self):
        """Uncommitted bytes which may still be promised to new channels."""
        with self._lock:
            return self.limit - self.allocated

    def __int__(self):
        return self.limit

    def __repr__(self):
        with self._lock:
            return (
                "<ReceiveCapacity limit={} occupied={} allocated={} "
                "channels={}>".format(
                    self.limit,
                    self.occupied,
                    self.allocated,
                    len(self._channels),
                )
            )

    def snapshot(self):
        """Return a lock-protected copy of global and per-channel counters."""
        with self._lock:
            return {
                "limit": self.limit,
                "occupied": self.occupied,
                "allocated": self.allocated,
                "available": self.limit - self.allocated,
                "channels": {
                    chanid: {
                        "window": a.window,
                        "buffered": a.buffered,
                        "pending_adjust": a.pending_adjust,
                        "occupied": a.window + a.buffered,
                        "allocated": (
                            a.window + a.buffered + a.pending_adjust
                        ),
                        "revoked": a.revoked,
                    }
                    for chanid, a in self._channels.items()
                },
            }

    # -- channel lifetime -----------------------------------------------------

    def reserve(self, chanid, window, channel=None, finalizer=True):
        """
        Reserve an initial advertised window for a new channel.

        Returns ``window`` on success.  Raises :class:`ReceiveCapacityError`
        if doing so would make hard commitments exceed the budget.
        """
        window = int(window)
        if window < 0:
            raise ValueError("window must be nonnegative")
        with self._lock:
            if chanid in self._channels:
                raise ReceiveCapacityError(
                    "Channel {} already has a receive capacity account".format(
                        chanid
                    )
                )
            if self.allocated + window > self.limit:
                raise ReceiveCapacityError(
                    "Not enough connection receive capacity for channel "
                    "{}: need {}, only {} uncommitted of {} bytes".format(
                        chanid,
                        window,
                        self.limit - self.allocated,
                        self.limit,
                    )
                )
            account = _ChannelBudget(window, channel)
            self._channels[chanid] = account
            self.occupied += window
            self.allocated += window
            if finalizer and channel is not None:
                # If an application drops an unread Channel, its pipes
                # disappear too.  Do not leave shared budget occupied forever.
                weakref.finalize(channel, self.discard, chanid)
            return window

    def can_reserve(self, window):
        with self._lock:
            return self.allocated + int(window) <= self.limit

    def discard(self, chanid):
        """
        Remove an account and release all of its bytes.

        This is for open failures and object finalization.  Normal EOF/close
        uses :meth:`revoke_window`, which preserves charges for still-readable
        buffered data.  It is idempotent.
        """
        with self._lock:
            account = self._channels.pop(chanid, None)
            if account is None:
                return 0
            occupied_delta = account.window + account.buffered
            allocated_delta = (
                account.window + account.buffered + account.pending_adjust
            )
            self.occupied -= occupied_delta
            self.allocated -= allocated_delta
            return allocated_delta

    def revoke_window(self, chanid):
        """
        Release window and pending-adjust credits which are no longer valid.

        Buffered bytes remain charged until the application reads them.  This
        method is idempotent.
        """
        with self._lock:
            account = self._channels.get(chanid)
            if account is None or account.revoked:
                return 0
            account.revoked = True
            released_occupied = account.window
            released_allocated = account.window + account.pending_adjust
            # Packets already permitted by the old window may be in flight.
            # Keep a private, non-budgeted allowance solely to distinguish
            # those from a genuine window violation.
            account.grace_window = max(
                account.grace_window, account.window
            )
            self.occupied -= released_occupied
            self.allocated -= released_allocated
            account.window = 0
            account.pending_adjust = 0
            self._delete_if_empty(chanid, account)
            return released_allocated

    # -- payload and read accounting -----------------------------------------

    def admit(self, chanid, length):
        """
        Validate an incoming payload and convert window credit to buffering.

        The caller must not add *length* bytes to a channel buffer if this
        raises.  Global occupancy is unchanged by a successful call because the
        same bytes move from "advertised window" to "unread payload".
        """
        length = int(length)
        if length < 0:
            raise ValueError("length must be nonnegative")
        with self._lock:
            account = self._channels.get(chanid)
            if account is None:
                raise ChannelWindowOverflow(chanid, length, 0)
            if account.revoked:
                # The budgeted window has already been reclaimed.  Accept and
                # discard only bytes which could have been sent under the
                # previous, valid advertisement; never grow a cache after
                # close/EOF.
                if length <= account.grace_window:
                    account.grace_window -= length
                    return "discard"
                raise ChannelWindowOverflow(
                    chanid, length, account.grace_window
                )
            if length > account.window:
                raise ChannelWindowOverflow(
                    chanid, length, account.window
                )
            account.window -= length
            account.buffered += length
            return "feed"

    def record_read(self, chanid, length):
        """
        Record bytes removed from a channel buffer.

        For an active channel the bytes are earmarked in
        ``pending_adjust``; for a revoked channel they leave the hard
        allocation as well.  Returns the number of bytes earmarked for a future
        adjustment.
        """
        length = int(length)
        if length <= 0:
            return 0
        with self._lock:
            account = self._channels.get(chanid)
            if account is None:
                # Should not happen for a live Channel, but never break recv()
                # because of bookkeeping.  The global bound is still safe.
                return 0
            if length > account.buffered:
                # Buffer accounting is authoritative; clamp rather than going
                # negative if a caller notifies twice for the same bytes.
                length = account.buffered
            account.buffered -= length
            self.occupied -= length
            if account.revoked:
                self.allocated -= length
                earmarked = 0
                self._delete_if_empty(chanid, account)
            else:
                account.pending_adjust += length
                # allocated intentionally unchanged
                earmarked = length
            return earmarked

    def flush_adjustment(self, chanid, requested):
        """
        Commit a sent WINDOW_ADJUST after the message has been handed off.

        This converts up to *requested* earmarked read bytes into the
        advertised-window counter.  The amount can never exceed pending
        accounting and therefore never needs to wait for global capacity.
        """
        requested = int(requested)
        if requested <= 0:
            return 0
        with self._lock:
            account = self._channels.get(chanid)
            if account is None or account.revoked:
                return 0
            amount = min(requested, account.pending_adjust)
            account.pending_adjust -= amount
            account.window += amount
            self.occupied += amount
            # allocated was already holding these bytes as pending_adjust.
            return amount

    def cancel_adjustment(self, chanid, requested):
        """Release earmarked bytes when an adjustment could not be prepared."""
        requested = int(requested)
        if requested <= 0:
            return 0
        with self._lock:
            account = self._channels.get(chanid)
            if account is None:
                return 0
            amount = min(requested, account.pending_adjust)
            account.pending_adjust -= amount
            self.allocated -= amount
            if account.revoked:
                self._delete_if_empty(chanid, account)
            return amount

    def rollback_committed_adjustment(self, chanid, requested):
        """Undo a window commit whose WINDOW_ADJUST write failed."""
        requested = int(requested)
        if requested <= 0:
            return 0
        with self._lock:
            account = self._channels.get(chanid)
            if account is None:
                return 0
            amount = min(requested, account.window)
            account.window -= amount
            self.occupied -= amount
            self.allocated -= amount
            if account.revoked:
                self._delete_if_empty(chanid, account)
            return amount

    def window(self, chanid):
        with self._lock:
            account = self._channels.get(chanid)
            return None if account is None else account.window

    def buffered(self, chanid):
        with self._lock:
            account = self._channels.get(chanid)
            return None if account is None else account.buffered

    def verify(self, channels=None):
        """
        Check internal arithmetic and, optionally, live Channel buffers.

        *channels* may be a mapping/iterable of channels to compare against.
        Pipe locks are acquired before the capacity lock, matching feed/read
        lock order and avoiding lock-order inversion.  Raises
        :class:`AssertionError` on inconsistency and returns a snapshot.
        """
        live_channels = self._materialize_channels(channels)
        live_channels.sort(key=lambda channel: channel.chanid)
        pipe_locks = []
        for channel in live_channels:
            stdout_lock = channel.in_buffer._lock
            stderr_lock = channel.in_stderr_buffer._lock
            stdout_lock.acquire()
            pipe_locks.append(stdout_lock)
            stderr_lock.acquire()
            pipe_locks.append(stderr_lock)

        try:
            with self._lock:
                assert 0 <= self.occupied <= self.allocated <= self.limit, (
                    self.occupied,
                    self.allocated,
                    self.limit,
                )
                occupied = 0
                allocated = 0
                by_id = {
                    channel.chanid: channel for channel in live_channels
                }
                for chanid, account in self._channels.items():
                    assert account.window >= 0
                    assert account.buffered >= 0
                    assert account.pending_adjust >= 0
                    occupied += account.window + account.buffered
                    allocated += (
                        account.window
                        + account.buffered
                        + account.pending_adjust
                    )
                    channel = by_id.get(chanid)
                    if channel is not None:
                        pipes = len(channel.in_buffer._buffer) + len(
                            channel.in_stderr_buffer._buffer
                        )
                        assert account.buffered == pipes, (
                            chanid,
                            account.buffered,
                            pipes,
                        )
                assert occupied == self.occupied, (
                    occupied,
                    self.occupied,
                )
                assert allocated == self.allocated, (
                    allocated,
                    self.allocated,
                )
            return self.snapshot()
        finally:
            for lock in reversed(pipe_locks):
                lock.release()

    @staticmethod
    def _materialize_channels(channels):
        if channels is None:
            return []
        if hasattr(channels, "values"):
            try:
                return [
                    channel
                    for channel in channels.values()
                    if channel is not None
                ]
            except Exception:
                pass
        materialized = []
        try:
            for channel in channels:
                if channel is not None:
                    materialized.append(channel)
        except TypeError:
            return []
        return materialized

    def _delete_if_empty(self, chanid, account):
        # Caller holds the lock.
        if (
            account.revoked
            and account.window == 0
            and account.buffered == 0
            and account.pending_adjust == 0
        ):
            self._channels.pop(chanid, None)


# Friendly aliases for callers/tests that describe the same budget differently.
SharedReceiveCapacity = ReceiveCapacity
ConnectionReceiveBudget = ReceiveCapacity
