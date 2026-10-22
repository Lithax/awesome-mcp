"""A fake QEMU guest agent on a unix socket: speaks the QGA JSON protocol, runs guest-exec locally."""
import base64, json, os, socket, subprocess, threading, time


class FakeGA:
    def __init__(self, path, one_client_at_a_time=True):
        self.path, self.procs, self.next_pid, self.lock = path, {}, 1000, threading.Lock()
        self.stale = b""
        if os.path.exists(path):
            os.unlink(path)
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(path)
        self.srv.listen(4)
        self.alive = True
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.alive = False
        try: self.srv.close()
        except OSError: pass

    def _accept(self):
        while self.alive:
            try: c, _ = self.srv.accept()
            except OSError: return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        c.sendall(b"")  # nothing on connect, like real QGA
        buf = b""
        with c:
            while True:
                try: chunk = c.recv(1 << 20)
                except OSError: return
                if not chunk: return
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.lstrip(b"\xff")
                    if not line.strip(): continue
                    req = json.loads(line)
                    reply, prefix = self.handle(req)
                    try: c.sendall(prefix + json.dumps(reply).encode() + b"\n")
                    except OSError: return

    def handle(self, req):
        cmd, a = req["execute"], req.get("arguments") or {}
        if cmd == "guest-sync-delimited":
            return {"return": a["id"]}, b"\xff"
        if cmd == "guest-ping":
            return {"return": {}}, b""
        if cmd == "guest-exec":
            env = dict(item.split("=", 1) for item in a.get("env", []))
            inp = base64.b64decode(a["input-data"]) if "input-data" in a else b""
            p = subprocess.Popen([a["path"], *a.get("arg", [])], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env)
            with self.lock:
                self.next_pid += 1
                pid = self.next_pid
                self.procs[pid] = p
            threading.Thread(target=self._feed, args=(p, inp), daemon=True).start()
            return {"return": {"pid": pid}}, b""
        if cmd == "guest-exec-status":
            p = self.procs.get(a["pid"])
            if p is None:
                return {"error": {"class": "GenericError", "desc": "PID not found"}}, b""
            if p.poll() is None:
                return {"return": {"exited": False}}, b""
            out = getattr(p, "_o", b""); err = getattr(p, "_e", b"")
            res = {"exited": True, "out-data": base64.b64encode(out).decode(), "err-data": base64.b64encode(err).decode()}
            if p.returncode < 0: res["signal"] = -p.returncode
            else: res["exitcode"] = p.returncode
            return {"return": res}, b""
        return {"error": {"class": "CommandNotFound", "desc": f"unsupported {cmd}"}}, b""

    @staticmethod
    def _feed(p, inp):
        o, e = p.communicate(inp)
        p._o, p._e = o, e
