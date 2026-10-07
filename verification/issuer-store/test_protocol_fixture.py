# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Guard the fault fixture's packet framing, including fragmented and truncated traffic."""
import socket
import struct
import threading
import unittest
from run import packet, exact


class ProtocolFixtureTests(unittest.TestCase):
    def streams(self):
        a, b = socket.socketpair()
        a.settimeout(2)
        b.settimeout(2)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        return a, b

    def test_fragmented_frame_is_preserved(self):
        a, b = self.streams()
        data = b'Q' + struct.pack('!I', 11) + b'COMMIT\0'
        def send():
            for byte in data:
                b.sendall(bytes([byte]))
        t = threading.Thread(target=send)
        t.start()
        kind, body, raw = packet(a)
        t.join(2)
        self.assertFalse(t.is_alive())
        self.assertEqual((kind, body, raw), (b'Q', b'COMMIT\0', data))

    def test_truncated_body_fails(self):
        a, b = self.streams()
        b.sendall(b'Q' + struct.pack('!I', 11) + b'CO')
        b.shutdown(socket.SHUT_WR)
        with self.assertRaises(EOFError):
            packet(a)

    def test_oversized_frame_fails_before_body(self):
        a, b = self.streams()
        b.sendall(b'Q' + struct.pack('!I', 131073))
        with self.assertRaises(ValueError):
            packet(a)

    def test_invalid_small_frame_fails(self):
        a, b = self.streams()
        b.sendall(b'Q' + struct.pack('!I', 3))
        with self.assertRaises(ValueError):
            packet(a)

    def test_ready_packet_is_not_inferred_from_command_complete(self):
        a, b = self.streams()
        b.sendall(b'C' + struct.pack('!I', 11) + b'COMMIT\0' + b'Z' + struct.pack('!I', 5) + b'I')
        self.assertEqual(packet(a)[:2], (b'C', b'COMMIT\0'))
        self.assertEqual(packet(a)[:2], (b'Z', b'I'))

    def test_empty_startup_is_eof(self):
        a, b = self.streams()
        b.shutdown(socket.SHUT_WR)
        with self.assertRaises(EOFError):
            exact(a, 4)


if __name__ == '__main__':
    unittest.main()
