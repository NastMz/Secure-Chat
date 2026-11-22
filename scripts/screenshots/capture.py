#!/usr/bin/env python3
"""Record real SecureChat terminal sessions and render them to HTML.

Each program runs inside a pseudo-terminal; its raw output (ANSI colors,
cursor movement, the redrawn prompt) is interpreted by the `pyte` terminal
emulator, and the final screen is written as a styled HTML page. A browser
then turns each page into a PNG (see render.sh). Nothing is mocked: every
character comes from the real binaries.

Usage: capture.py BUILD_DIR OUT_DIR
"""

import fcntl
import html
import os
import pty
import re
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time

import pyte

COLS, ROWS = 92, 24

BASIC = {
    "black": "#1b2026", "red": "#f0716b", "green": "#7fd08a", "brown": "#e8c46a",
    "yellow": "#e8c46a", "blue": "#6aa7ee", "magenta": "#c79bf0", "cyan": "#5fd4cf",
    "white": "#d8dde3",
}
FOREGROUND = "#d4dae0"
BACKGROUND = "#11161c"


class Terminal:
    """A program running in a pty, mirrored into a pyte screen."""

    def __init__(self, argv, env, cols=COLS, rows=ROWS, cwd=None):
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self.lock = threading.Lock()
        self.raw = b""
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                     env=env, cwd=cwd, start_new_session=True)
        os.close(slave)
        self.master = master
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            try:
                data = os.read(self.master, 4096)
            except OSError:
                return
            if not data:
                return
            with self.lock:
                self.raw += data
                self.stream.feed(data)

    def type(self, text, delay=0.02):
        for ch in text:
            os.write(self.master, ch.encode())
            time.sleep(delay)

    def enter(self, text="", delay=0.02):
        self.type(text, delay)
        os.write(self.master, b"\r")
        time.sleep(0.35)

    def wait_for(self, pattern, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                text = "\n".join(self.screen.display)
            if re.search(pattern, text):
                return
            time.sleep(0.05)
        raise RuntimeError("timeout waiting for %r in:\n%s" % (pattern, text))

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def to_html(self, title, show_cursor=True):
        with self.lock:
            return render_html(self.screen, title, show_cursor)


def color(value, default):
    if value in ("default", None):
        return default
    if value in BASIC:
        return BASIC[value]
    if value.startswith("bright") and value[6:] in BASIC:
        return BASIC[value[6:]]
    if re.fullmatch(r"[0-9a-fA-F]{6}", value):
        return "#" + value
    return default


def render_html(screen, title, show_cursor):
    rows = []
    for y in range(screen.lines):
        line = screen.buffer[y]
        spans = []
        current = None
        text = ""
        for x in range(screen.columns):
            ch = line[x]
            fg = color(ch.fg, FOREGROUND)
            bg = color(ch.bg, None)
            if ch.reverse:
                fg, bg = (bg or BACKGROUND), fg
            cursor = show_cursor and x == screen.cursor.x and y == screen.cursor.y
            style = (fg, bg, ch.bold, cursor)
            if style != current:
                if current is not None:
                    spans.append((current, text))
                current, text = style, ""
            text += ch.data or " "
        spans.append((current, text))
        parts = []
        for (fg, bg, bold, cursor), chunk in spans:
            css = "color:%s;" % fg
            if bg:
                css += "background:%s;" % bg
            if bold:
                css += "font-weight:700;"
            cls = ' class="cursor"' if cursor else ""
            parts.append('<span%s style="%s">%s</span>' % (cls, css, html.escape(chunk)))
        rows.append("".join(parts).rstrip())
    body = "\n".join(rows)
    return TEMPLATE.replace("{{TITLE}}", html.escape(title)).replace("{{BODY}}", body)


TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{{TITLE}}</title>
<style>
  html, body { margin: 0; background: #0a0d11; }
  body { display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .frame { margin: 28px; border-radius: 12px; overflow: hidden;
           box-shadow: 0 18px 50px rgba(0,0,0,.55), 0 0 0 1px #232b35;
           background: """ + BACKGROUND + """; display: inline-block; }
  .bar { height: 38px; display: flex; align-items: center; gap: 8px;
         padding: 0 16px; background: #171d25; border-bottom: 1px solid #232b35;
         font: 600 13px/1 "Segoe UI", system-ui, sans-serif; color: #8b97a5; }
  .dot { width: 11px; height: 11px; border-radius: 50%; background: #2c3541; }
  .dot.teal { background: #22b3a3; }
  .title { margin-left: 10px; letter-spacing: .02em; }
  pre { margin: 0; padding: 18px 22px 22px; color: """ + FOREGROUND + """;
        font: 15px/1.45 "Cascadia Mono", "Cascadia Code", Consolas, monospace; }
  .cursor { background: #5fd4cf !important; color: #11161c !important; }
</style></head>
<body><div class="frame"><div class="bar"><span class="dot teal"></span>
<span class="dot"></span><span class="dot"></span><span class="title">{{TITLE}}</span></div>
<pre>{{BODY}}</pre></div></body></html>
"""


def save(out_dir, name, term, title, show_cursor=True):
    path = os.path.join(out_dir, name + ".html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(term.to_html(title, show_cursor))
    print("wrote", path)


def main():
    build, out_dir = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    os.makedirs(out_dir, exist_ok=True)
    server_bin = os.path.join(build, "securechat-server")
    client_bin = os.path.join(build, "securechat-client")
    tmp = tempfile.mkdtemp(prefix="securechat-demo-")
    base_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "TERM": "xterm-256color",
                "LANG": "C.UTF-8", "HOME": tmp}
    key = os.path.join(tmp, "server.key")

    out = subprocess.run([server_bin, "--key", key, "--show-key"],
                         capture_output=True, text=True, check=True).stdout
    pubkey = re.search(r"public key:\s+([0-9a-f]{64})", out).group(1)

    server = Terminal([server_bin, "--port", "7000", "--key", key], base_env, rows=18)
    server.wait_for("listening")

    def client_env(name):
        home = os.path.join(tmp, name)
        os.makedirs(home, exist_ok=True)
        return dict(base_env, SECURECHAT_HOME=home)

    alice = Terminal([client_bin, "--host", "localhost", "--server-key", pubkey],
                     client_env("alice"))
    bob = Terminal([client_bin, "--host", "localhost"], client_env("bob"))
    alice.wait_for("username")
    bob.wait_for("username")

    alice.enter("alice")
    alice.wait_for("Welcome, alice")
    bob.enter("bob")
    bob.wait_for("Welcome, bob")
    time.sleep(0.4)
    alice.enter("hi bob! did the new build pass the sanitizer run?")
    bob.wait_for("sanitizer run")
    bob.enter("yes, ASan and UBSan are clean. what's left for the release?")
    alice.wait_for("release")
    alice.enter("just the screenshots and the README")
    bob.enter("/msg alice can you review my threat model section before we publish?")
    alice.wait_for("threat model")
    alice.enter("/msg bob sure, send it over. only you can read this one")
    bob.wait_for("only you can read")

    carol = Terminal([client_bin, "--host", "localhost"], client_env("carol"))
    carol.wait_for("username")
    carol.enter("carol")
    carol.wait_for("Welcome, carol")
    alice.wait_for("carol joined")
    bob.type("brb, grabbing a coff")  # left unsent: the prompt keeps it
    alice.enter("welcome carol! /list shows everyone's key fingerprint")
    carol.wait_for("welcome carol")
    carol.enter("/list")
    carol.wait_for("online")
    carol.enter("/whois alice")
    carol.wait_for("another channel")
    carol.enter("/fingerprint")
    carol.wait_for("server identity")
    time.sleep(0.5)

    save(out_dir, "01-chat-alice", alice, "alice — securechat-client")
    save(out_dir, "02-chat-bob", bob, "bob — securechat-client")
    save(out_dir, "03-roster-fingerprints", carol, "carol — securechat-client")

    alice.enter("/help")
    alice.wait_for("leave the chat")
    time.sleep(0.3)
    save(out_dir, "04-help", alice, "alice — securechat-client")

    carol.enter("/quit")
    time.sleep(0.5)
    bob.type("\x15")
    bob.enter("/quit")
    time.sleep(0.6)
    save(out_dir, "05-server-log", server, "securechat-server", show_cursor=False)

    # A client pinned to the wrong key refuses to talk to the server.
    shell = Terminal(["bash", "--norc", "--noprofile"],
                     dict(base_env, PATH=build + ":" + base_env["PATH"], PS1="\\[\\e[38;5;43m\\]demo@securechat\\[\\e[0m\\]:\\[\\e[38;5;244m\\]~\\[\\e[0m\\]$ "),
                     rows=14)
    time.sleep(0.4)
    shell.enter("securechat-client --host localhost --server-key " + "ab" * 32, delay=0.002)
    shell.wait_for("Aborting")
    time.sleep(0.3)
    save(out_dir, "06-mitm-alert", shell, "securechat-client — pinned key mismatch")

    for t in (alice, bob, carol, shell, server):
        t.stop()


if __name__ == "__main__":
    main()
