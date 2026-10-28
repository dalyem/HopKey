"""A minimal MCP stdio client (newline-delimited JSON-RPC) for hop mcp."""
import json
import os
import select
import subprocess
import time

import e2elib as L


class MCP:
    def __init__(self, args=(), user='tester', nopass=False, env=None, tag='mcp'):
        argv = L.user_argv(user, ['hop', 'mcp'] + list(args), 600)
        self.stderr_path = '%s/logs/%s.stderr' % (L.E2E, tag)
        self.p = subprocess.Popen(argv, env=L.user_env(user, nopass, env), stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=open(self.stderr_path, 'w'),
                                  text=True, bufsize=1, cwd='/tmp')
        self.nid = 0
        self.transcript = []  # every raw response line, for the secret scan
        self.buf = b''
        self.hung = False      # a request went unanswered past its timeout
        self.exited = False    # hop mcp closed its stdout
        self.answered = 0      # responses that carried a result or an error from hop mcp
        self.init = self.rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                            'clientInfo': {'name': 'hk-e2e', 'version': '1'}})
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def send(self, msg):
        try:
            self.p.stdin.write(json.dumps(msg) + '\n')
            self.p.stdin.flush()
        except (BrokenPipeError, ValueError):
            self.exited = True

    def _line(self, deadline):
        """The next stdout line, '' at EOF, None at the deadline (reads the fd, so select sees all data)."""
        fd = self.p.stdout.fileno()
        while b'\n' not in self.buf:
            left = deadline - time.time()
            if left <= 0:
                return None
            r, _, _ = select.select([fd], [], [], left)
            if not r:
                continue
            d = os.read(fd, 65536)
            if not d:
                return ''
            self.buf += d
        line, self.buf = self.buf.split(b'\n', 1)
        return line.decode(errors='replace') + '\n'

    def rpc(self, method, params, timeout=120):
        self.nid += 1
        self.send({'jsonrpc': '2.0', 'id': self.nid, 'method': method, 'params': params})
        deadline = time.time() + timeout
        while True:
            if self.exited:
                return {'error': {'message': 'EOF from hop mcp'}, 'transport': 'eof'}
            line = self._line(deadline)
            if line is None:
                self.hung = True
                return {'error': {'message': 'timeout'}, 'transport': 'timeout'}
            if not line:
                self.exited = True
                return {'error': {'message': 'EOF from hop mcp'}, 'transport': 'eof'}
            self.transcript.append(line)
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get('id') == self.nid:
                self.answered += 1
                return m

    def tools(self):
        r = self.rpc('tools/list', {})
        return [t['name'] for t in r.get('result', {}).get('tools', [])], r

    def call(self, name, args):
        """Returns (is_error, structured or None, text); the raw response is in last_raw."""
        r = self.rpc('tools/call', {'name': name, 'arguments': args})
        self.last_raw = r
        res = r.get('result')
        if res is None:
            return True, None, json.dumps(r.get('error'))
        text = '\n'.join(c.get('text', '') for c in res.get('content', []) if c.get('type') == 'text')
        L.log('MCP', name, json.dumps(args), '->', 'isError=%s' % res.get('isError'), text[:600])
        return bool(res.get('isError')), res.get('structuredContent'), text

    @property
    def healthy(self):
        """Every request so far got an answer from hop mcp (no hang, no exit)."""
        return not self.hung and not self.exited and self.answered == self.nid

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=20)
        except Exception:
            self.p.kill()
            self.p.wait()
        return self.p.returncode

    def stderr(self):
        try:
            return open(self.stderr_path).read()
        except OSError:
            return ''


def results(struct):
    """exec/run_snippet results by host."""
    return {r['host']: r for r in (struct or {}).get('results', [])}
