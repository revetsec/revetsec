# Copyright 2026 Revetware LLC. Licensed under Apache-2.0.
"""Owned fixture protocol fault transport reused from issuer-store/run.py, with explicit read-COMMIT fault selection.

No raw SQL, protocol payload, credentials or sealed data is retained.
"""
import socket
import select
import struct
import threading

def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        piece = stream.recv(count - len(data))
        if not piece:
            raise EOFError('Fixture connection closed')
        data.extend(piece)
    return bytes(data)

def packet(stream):
    kind = exact(stream, 1)
    length = struct.unpack('!I', exact(stream, 4))[0]
    if not 4 <= length <= 131072:
        raise ValueError('Fixture packet bound')
    body = exact(stream, length - 4)
    return kind, body, kind + struct.pack('!I', length) + body

class CommitLossProxy:
    """Plaintext *owned test* PostgreSQL v3 proxy, simple-query mode only.

    Drops exactly one writing COMMIT before forwarding, or withholds its whole response
    until authoritative ReadyForQuery confirms server commit, then closes the client.
    Read COMMITs are forwarded. Raw protocol bytes/queries are never retained or logged.
    """
    def __init__(self, port, when, drop_read_commits=False):
        self.drop_read_commits = drop_read_commits
        self.port, self.when = port, when
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(.2)
        self.local_port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.drops = 0
        self.committed_ready = 0
        self.errors = []
        self.sockets = []
        self.threads = []
        self.acceptor = threading.Thread(target=self.accept, daemon=True)
        self.acceptor.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                server = socket.create_connection(('127.0.0.1', self.port), timeout=5)
            except OSError:
                client.close()
                if not self.stop.is_set():
                    self.errors.append('owned-primary-connect')
                continue
            if self.stop.is_set():
                client.close()
                server.close()
                return
            self.sockets += [client, server]
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client.settimeout(2)
            server.settimeout(2)
            thread = threading.Thread(target=self.forward, args=(client, server), daemon=True)
            self.threads.append(thread)
            thread.start()

    def forward(self, client, server):
        # One owner per connection avoids concurrent close/recv on the same socket.
        dirty = False
        withholding = False
        try:
            size = struct.unpack('!I', exact(client, 4))[0]
            if not 8 <= size <= 4096:
                raise ValueError('Startup bound')
            startup = exact(client, size - 4)
            if startup[:4] != b'\x00\x03\x00\x00':
                raise ValueError('Expected plaintext v3 owned fixture')
            server.sendall(struct.pack('!I', size) + startup)
            while not self.stop.is_set():
                readable, _, _ = select.select([client, server], [], [], .2)
                for stream in readable:
                    kind, body, raw = packet(stream)
                    if stream is client:
                        if kind == b'Q':
                            upper = body.upper()
                            dirty |= upper.lstrip(b'\x00; \r\n\t').startswith((b'INSERT ', b'UPDATE ', b'DELETE '))
                            if upper.strip(b'\x00; \r\n\t') == b'COMMIT' and (dirty or self.drop_read_commits):
                                with self.lock:
                                    selected = self.drops == 0
                                    if selected:
                                        self.drops += 1
                                if selected and self.when == 'before':
                                    return
                                withholding = selected
                        server.sendall(raw)
                    elif withholding:
                        if kind == b'Z':
                            if body != b'I':
                                self.errors.append('commit-not-idle')
                            else:
                                self.committed_ready += 1
                            return
                    else:
                        client.sendall(raw)
                        if kind == b'Z' and body == b'I':
                            dirty = False
        except (EOFError, OSError):
            pass
        except ValueError:
            self.errors.append('protocol-bound')
        finally:
            for stream in [client, server]:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                stream.close()

    def close(self):
        self.stop.set()
        try:
            self.listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.listener.close()
        # Wake accept explicitly and finish registration before closing worker sockets.
        self.acceptor.join(6)
        for stream in self.sockets:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for thread in self.threads:
            thread.join(3)
        for stream in self.sockets:
            stream.close()
        if self.acceptor.is_alive() or any(t.is_alive() for t in self.threads):
            raise RuntimeError('Proxy fixture threads did not stop')
