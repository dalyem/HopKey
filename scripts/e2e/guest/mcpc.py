"""A minimal MCP stdio client (newline-delimited JSON-RPC) for hop mcp."""
import json
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
        self.init = self.rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                            'clientInfo': {'name': 'hk-e2e', 'version': '1'}})
        self.send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})

    def send(self, msg):
        self.p.stdin.write(json.dumps(msg) + '\n')
        self.p.stdin.flush()

    def rpc(self, method, params, timeout=120):
        self.nid += 1
        self.send({'jsonrpc': '2.0', 'id': self.nid, 'method': method, 'params': params})
        t0 = time.time()
        while True:
            line = self.p.stdout.readline()
            if not line:
                return {'error': {'message': 'EOF from hop mcp'}}
            self.transcript.append(line)
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get('id') == self.nid:
                return m
            if time.time() - t0 > timeout:
                return {'error': {'message': 'timeout'}}

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

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=20)
        except Exception:
            self.p.kill()
        return self.p.returncode

    def stderr(self):
        try:
            return open(self.stderr_path).read()
        except OSError:
            return ''


def results(struct):
    """exec/run_snippet results by host."""
    return {r['host']: r for r in (struct or {}).get('results', [])}
