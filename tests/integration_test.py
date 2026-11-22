#!/usr/bin/env python3
"""End-to-end test of SecureChat.

Starts the real server, puts a recording TCP proxy in front of it and drives
real clients through the proxy. Verifies chat, private messages, join/leave
notices, server authentication (pinned key and TOFU), robustness against
malformed input, graceful shutdown, and that nothing readable crosses the
wire. Uses only the Python standard library.

Usage: integration_test.py BUILD_DIR
"""

import os
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

TIMEOUT = 15.0
SANITIZER_MARKERS = ("AddressSanitizer", "LeakSanitizer", "runtime error:")

checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)
    print(f"  ok   {message}")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Process:
    """A child process with captured stdout/stderr and line-based stdin."""

    def __init__(self, argv, env=None):
        self.argv = argv
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env)
        self.out = ""
        self.err = ""
        self.lock = threading.Lock()
        self.threads = [
            threading.Thread(target=self._pump, args=(self.proc.stdout, "out"), daemon=True),
            threading.Thread(target=self._pump, args=(self.proc.stderr, "err"), daemon=True),
        ]
        for t in self.threads:
            t.start()

    def _pump(self, stream, attr):
        for raw in iter(lambda: stream.read1(4096), b""):
            with self.lock:
                setattr(self, attr, getattr(self, attr) + raw.decode("utf-8", "replace"))

    def wait_for(self, pattern, timeout=TIMEOUT):
        deadline = time.time() + timeout
        regex = re.compile(pattern)
        while time.time() < deadline:
            with self.lock:
                if regex.search(self.out):
                    return True
            if self.proc.poll() is not None:
                time.sleep(0.2)
                with self.lock:
                    return bool(regex.search(self.out))
            time.sleep(0.05)
        return False

    def send(self, line):
        self.proc.stdin.write((line + "\n").encode())
        self.proc.stdin.flush()

    def close_stdin(self):
        self.proc.stdin.close()

    def wait(self, timeout=TIMEOUT):
        code = self.proc.wait(timeout=timeout)
        for t in self.threads:
            t.join(timeout=2)
        return code

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


class RecordingProxy:
    """Forwards TCP connections to the server and records every byte."""

    def __init__(self, target_port):
        self.target_port = target_port
        self.data = bytearray()
        self.lock = threading.Lock()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            upstream = socket.create_connection(("127.0.0.1", self.target_port))
            for a, b in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    def _pipe(self, src, dst):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                with self.lock:
                    self.data += chunk
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def captured(self):
        with self.lock:
            return bytes(self.data)


def recv_closed(sock, timeout=5.0):
    """True when the peer closes the connection (EOF or reset)."""
    sock.settimeout(timeout)
    try:
        while True:
            if not sock.recv(4096):
                return True
    except ConnectionResetError:
        return True
    except socket.timeout:
        return False


def main():
    build = sys.argv[1] if len(sys.argv) > 1 else "build"
    server_bin = os.path.join(build, "securechat-server")
    client_bin = os.path.join(build, "securechat-client")
    processes = []

    with tempfile.TemporaryDirectory(prefix="securechat-it-") as tmp:
        key_path = os.path.join(tmp, "server.key")
        env = dict(os.environ, SECURECHAT_HOME=tmp, NO_COLOR="1")

        show = subprocess.run([server_bin, "--key", key_path, "--show-key"],
                              capture_output=True, text=True, check=True)
        pubkey = re.search(r"public key:\s+([0-9a-f]{64})", show.stdout).group(1)
        check(os.stat(key_path).st_mode & 0o777 == 0o600, "server key file is created with mode 0600")

        port = free_port()
        server = Process([server_bin, "--port", str(port), "--bind", "127.0.0.1",
                          "--key", key_path, "--color", "never"], env)
        processes.append(server)
        check(server.wait_for(r"listening\s+127\.0\.0\.1:%d" % port), "server starts and listens")
        proxy = RecordingProxy(port)

        def client(*args, name=None, pin=True, known_hosts=None):
            argv = [client_bin, "--host", "127.0.0.1", "--port", str(proxy.port),
                    "--color", "never"]
            if pin:
                argv += ["--server-key", pubkey]
            if known_hosts:
                argv += ["--known-hosts", known_hosts]
            if name:
                argv += ["--name", name]
            p = Process(argv + list(args), env)
            processes.append(p)
            return p

        try:
            # --- server authentication -----------------------------------------
            bad_pin = "00" * 32
            p = Process([client_bin, "--host", "127.0.0.1", "--port", str(proxy.port),
                         "--server-key", bad_pin, "--name", "mallory"], env)
            processes.append(p)
            check(p.wait() == 1 and "SECURITY ALERT" in p.err,
                  "client aborts when the server key does not match --server-key")

            kh = os.path.join(tmp, "known_hosts_test")
            first = client(pin=False, known_hosts=kh, name="tofu")
            check(first.wait_for(r"first connection"), "TOFU: first connection remembers the server key")
            first.close_stdin()
            check(first.wait() == 0, "TOFU client exits cleanly")
            second = client(pin=False, known_hosts=kh, name="tofu")
            check(second.wait_for(r"matches the key remembered"), "TOFU: second connection matches the stored key")
            second.close_stdin()
            second.wait()
            with open(kh, "w") as f:
                f.write("127.0.0.1:%d %s\n" % (proxy.port, "ab" * 32))
            third = client(pin=False, known_hosts=kh, name="tofu")
            check(third.wait() == 1 and "has CHANGED" in third.err,
                  "TOFU: a changed server key aborts the connection")

            # --- chat between two clients --------------------------------------
            alice = client(name="alice")
            check(alice.wait_for(r"Welcome, alice"), "alice joins")
            bob = client(name="bob")
            check(bob.wait_for(r"Welcome, bob! 2 online"), "bob joins and sees 2 users online")
            check(alice.wait_for(r"bob joined the room"), "alice receives bob's join notice")

            alice.send("PUBLIC-CANARY hello everyone ¿qué tal?")
            check(bob.wait_for(r"alice\s+│ PUBLIC-CANARY hello everyone ¿qué tal\?"),
                  "bob receives alice's broadcast (UTF-8 intact)")
            check(alice.wait_for(r"alice\s+› PUBLIC-CANARY"), "alice sees her own message echoed")

            bob.send("/msg alice PRIVATE-CANARY just for you")
            check(alice.wait_for(r"bob → you │ PRIVATE-CANARY just for you"),
                  "alice receives bob's end-to-end encrypted private message")
            check(bob.wait_for(r"you → alice │ PRIVATE-CANARY"), "bob sees the private message he sent")

            alice.send("/msg nobody hi")
            check(alice.wait_for(r"No user named 'nobody'"), "private message to an unknown user is refused")
            alice.send("/list")
            check(alice.wait_for(r"2 online"), "/list shows both users")
            alice.send("/whois bob")
            check(alice.wait_for(r"bob e2e key [0-9A-F]{4} "), "/whois shows bob's key fingerprint")

            # A line typed before WELCOME arrives is sent as chat, not as a
            # second username attempt.
            dave = client(name="dave")
            dave.send("EARLY-LINE typed while joining")
            check(alice.wait_for(r"dave\s+│ EARLY-LINE typed while joining"),
                  "input typed during the join is delivered as chat")
            dave.send("/quit")
            check(dave.wait() == 0, "dave quits cleanly")

            # Username uniqueness is case-insensitive; the client may retry.
            carol = client(name="ALICE")
            check(carol.wait_for(r"already taken"), "duplicate username (case-insensitive) is rejected")
            carol.send("carol")
            check(carol.wait_for(r"Welcome, carol"), "user can retry with another name")
            carol.send("/quit")
            check(carol.wait() == 0, "carol quits cleanly")
            check(alice.wait_for(r"carol left the room"), "leave notice is broadcast")

            # --- hostile input does not affect other users ---------------------
            raw = socket.create_connection(("127.0.0.1", port))
            raw.sendall(struct.pack(">I", 0xFFFFFFFF) + b"x" * 64)
            check(recv_closed(raw), "server drops a connection announcing an oversized frame")
            raw.close()

            raw = socket.create_connection(("127.0.0.1", port))
            raw.sendall(struct.pack(">I", 37) + b"EVIL" + b"\x01" + b"\x00" * 32)
            check(recv_closed(raw), "server drops a connection with an invalid handshake")
            raw.close()

            raw = socket.create_connection(("127.0.0.1", port))
            raw.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            check(recv_closed(raw), "server drops non-protocol traffic")
            raw.close()

            alice.send("still alive")
            check(bob.wait_for(r"alice\s+│ still alive"), "chat keeps working after hostile connections")

            # --- leave and shutdown ----------------------------------------------
            bob.send("/quit")
            check(bob.wait() == 0, "bob quits with exit code 0")
            check(alice.wait_for(r"bob left the room"), "alice receives bob's leave notice")

            server.proc.send_signal(signal.SIGTERM)
            check(alice.wait_for(r"server is shutting down"), "clients are told about a graceful shutdown")
            check(server.wait() == 0, "server exits with code 0 on SIGTERM")
            check(alice.wait() == 0, "alice exits cleanly after the server goes away")

            # --- what an eavesdropper sees ----------------------------------------
            wire = proxy.captured()
            check(len(wire) > 1000, "the proxy captured the traffic (%d bytes)" % len(wire))
            check(b"SCH1" in wire, "only the handshake magic is visible in clear")
            for secret in (b"PUBLIC-CANARY", b"PRIVATE-CANARY", "¿qué".encode(),
                           b"alice", b"bob", b"carol", b"dave", b"EARLY-LINE", b"still alive"):
                check(secret not in wire, "wire capture does not contain %r" % secret)
            check("PRIVATE-CANARY" not in server.out, "server log does not contain private text")
        finally:
            for p in processes:
                p.kill()

        for p in processes:
            for marker in SANITIZER_MARKERS:
                if marker in p.err:
                    print(p.err, file=sys.stderr)
                    raise AssertionError("sanitizer report from %s" % p.argv[0])
        check(True, "no sanitizer reports from any process")

    print("integration: %d checks, 0 failures" % checks)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print("  FAIL %s" % exc, file=sys.stderr)
        sys.exit(1)
