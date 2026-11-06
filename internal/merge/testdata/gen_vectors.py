"""Regenerates vectors.json: known answers for the §5.4 / §4.4 digests.

This is an independent implementation (Python's hashlib and a small JCS
writer) of D(label, obj) = SHA-256(lp(label) || lp(JCS(obj))), so that the Go
code is checked against something that shares none of its code. Every string
here is BMP text without control characters other than LF, for which Python's
json.dumps with sort_keys and no ASCII escaping is RFC 8785 output.

Run from this directory:  python3 -I gen_vectors.py
"""
import hashlib
import json
import struct


def jcs(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def lp(b):
    return struct.pack(">I", len(b)) + b


def D(label, obj):
    msg = jcs(obj)
    h = hashlib.sha256(lp(label.encode()) + lp(msg.encode())).hexdigest()
    return msg, h


def header(item_id, typ, version):
    return {"v": 1, "item_id": item_id, "type": typ, "item_version": version}


def host(version, **over):
    h = header("11111111111111111111111111111111", "host", version)
    h.update({
        "name": "web", "aliases": ["w"], "addresses": ["10.0.0.1"], "port": 22,
        "user": "root", "key_id": "", "credential_id": "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
        "jump_host_id": "", "tags": ["prod"], "description": "front door",
        "tailscale": None, "route": "auto", "host_keys": [], "agent_access": "allow",
    })
    h.update(over)
    return h


credential = {**header("c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", "credential", "2"),
              "name": "root login", "username": "root", "password": "hunter2"}
snippet = {**header("5050505050505050505050505050505a", "snippet", "1"),
           "name": "restart", "command": "systemctl restart {{unit}}\nsystemctl status {{unit}}",
           "params": ["unit"], "description": "redémarrer une unité"}
key = {**header("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", "key", "5"),
       "name": "deploy", "key_type": "ed25519",
       "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
       "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBase deploy", "dedicated_grant": ""}

out = {
    "description": "Known-answer vectors for crypto spec rev 16 §5.4 and §4.4. "
                   "message is the JCS bytes that D hashes; digest is "
                   "SHA-256(lp(label) || lp(message)) in lowercase hex. "
                   "Regenerate with gen_vectors.py.",
    "resolve": [], "merge_discard": [], "merge_item": [],
}

# hopkey/v1/resolve: {"n":u64s, "action", "seen":item|null, "want":item|null}
for name, n, action, seen, want in [
    ("put", "7", "put", host("3"),
     host("3", addresses=["10.0.0.2"], credential_id="c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1")),
    ("create", "0", "create", None, snippet),
    ("delete, n is the largest u64", "18446744073709551615", "delete", credential, None),
]:
    msg, digest = D("hopkey/v1/resolve", {"n": n, "action": action, "seen": seen, "want": want})
    out["resolve"].append({"name": name, "label": "hopkey/v1/resolve", "n": n, "action": action,
                           "seen": seen, "want": want, "message": msg, "digest": digest})

# hopkey/v1/merge-item: the plaintext with item_version "1"
item_digest = {}
for name, item in [("key at version 5", key), ("snippet", snippet), ("credential at version 2", credential)]:
    one = {**item, "item_version": "1"}
    msg, digest = D("hopkey/v1/merge-item", one)
    item_digest[item["item_id"]] = digest
    out["merge_item"].append({"name": name, "label": "hopkey/v1/merge-item", "plaintext": item,
                              "message": msg, "digest": digest})

# hopkey/v1/merge-discard: items sorted by item_id. rows is in input order.
vault = "0123456789abcdef0123456789abcdef"
txn = "fedcba9876543210fedcba9876543210"
rows = [{"item_id": i["item_id"], "type": i["type"], "digest": item_digest[i["item_id"]]}
        for i in (credential, snippet, key)]  # item_ids c0…, 50…, a0…: not in order
for name, r in [("three rows, unsorted input", rows), ("no rows", [])]:
    sorted_rows = sorted(r, key=lambda x: x["item_id"])
    msg, digest = D("hopkey/v1/merge-discard", {"vault_id": vault, "txn_id": txn, "items": sorted_rows})
    out["merge_discard"].append({"name": name, "label": "hopkey/v1/merge-discard", "vault_id": vault,
                                 "txn_id": txn, "rows": r, "message": msg, "digest": digest})

with open("vectors.json", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
    f.write("\n")
