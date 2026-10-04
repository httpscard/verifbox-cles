#!/usr/bin/env python3
"""
verifbox_verify.py - Independent verifier for VerifBox timestamp proofs (format verifbox-preuve-1).

Checks, without contacting the VerifBox service:
  - the file's SHA-256 fingerprint against the proof,
  - the Ed25519 and ML-DSA-65 (FIPS 204) signatures,
  - the signing key: identifier, attestation chain, validity period, revocation status,
  - the public key file against its independent publication in the DNS of
    internetidentitycard.com (TXT record _verifbox, DNSSEC-validated), unless --offline.
The Bitcoin anchor is checked separately with the official OpenTimestamps client:
  this tool extracts the .ots file for that purpose (--ots).

Install:   pip install cryptography dilithium-py
Usage:     python3 verifbox_verify.py PROOF.verifbox.json [ORIGINAL_FILE] [--keys verifbox-cles.json] [--ots OUT.ots] [--offline]
                                     [--root KEYID:SHA256]

Trust: the root key is PINNED in this file by the SHA-256 of its two public keys (PINNED_ROOTS). A key file
can only add keys that are attested by a trusted key; an unknown root key is rejected.

Without --keys, the public keys are downloaded from https://verifbox.com/.well-known/verifbox-cles.json
and their SHA-256 fingerprint is printed, so you can compare it with independent publications.
Specification: https://verifbox.com/specification
Exit code: 0 = valid, 1 = invalid, 2 = error.  Licence: MIT.
"""
import argparse, base64, hashlib, json, sys, urllib.request
from datetime import datetime

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from dilithium_py.ml_dsa import ML_DSA_65
except ImportError:
    sys.exit("Missing dependencies: pip install cryptography dilithium-py")

KEYS_URL = "https://verifbox.com/.well-known/verifbox-cles.json"
DNS_NAME = "_verifbox.internetidentitycard.com"
DOH_URL = "https://dns.google/resolve?type=TXT&do=1&name=" + DNS_NAME
PROOF_PREFIX, TRANSITION_PREFIX = b"verifbox-preuve-v1\n", b"verifbox-transition-v1\n"
# Trusted root keys: identifier -> SHA-256(Ed25519 public key || ML-DSA-65 public key), full 256 bits.
PINNED_ROOTS = {"258e57366bcdb6ce": "258e57366bcdb6ce16cc22fe972c638346de2a5415327154a030e5a6b9293946"}
MAX_PROOF_SIZE = 1 << 20
CONTENT_FIELDS = ["algorithme", "cle", "emetteur", "empreinte", "format", "horodatage", "identifiant"]
OTS_MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")


def b64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj):
    """Sorted keys, no whitespace, ASCII only; every value must be a string."""
    for k, v in obj.items():
        if not isinstance(v, str) or not (k + v).isascii():
            raise ValueError("non-canonical content")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def signatures_ok(message, sigs, key):
    ed = pq = False
    try:
        Ed25519PublicKey.from_public_bytes(b64u(key["ed25519_public"])).verify(b64u(sigs["ed25519"]), message); ed = True
    except Exception:
        pass
    try:
        pq = bool(ML_DSA_65.verify(b64u(key["mldsa65_public"]), message, b64u(sigs["ml_dsa_65"])))
    except Exception:
        pass
    return ed, pq


def full_key_hash(entry):
    return hashlib.sha256(b64u(entry["ed25519_public"]) + b64u(entry["mldsa65_public"])).hexdigest()


def check_schema(proof):
    """Strict format verifbox-preuve-1. Returns the list of invalid items (empty if valid)."""
    import re
    c, s, bad = proof.get("contenu"), proof.get("signatures"), []
    if not isinstance(c, dict): return ["contenu"]
    if sorted(c) != CONTENT_FIELDS: bad.append("fields")
    if c.get("format") != "verifbox-preuve-1": bad.append("format")
    if c.get("emetteur") != "verifbox.com": bad.append("emetteur")
    if c.get("algorithme") != "SHA-256": bad.append("algorithme")
    for field, pattern in (("empreinte", r"[0-9a-f]{64}"), ("identifiant", r"[0-9a-f]{32}"), ("cle", r"[0-9a-f]{16}"),
                           ("horodatage", r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z")):
        if not isinstance(c.get(field), str) or not re.fullmatch(pattern, c[field]): bad.append(field)
    for field, size in (("ed25519", 64), ("ml_dsa_65", 3309)):
        try:
            value = (s or {}).get(field)
            if not (isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]+", value) and len(b64u(value)) == size): bad.append(field)
        except Exception:
            bad.append(field)
    return bad


def key_id(entry):
    """Identifier = first 16 hex characters of SHA-256(Ed25519 public key || ML-DSA-65 public key)."""
    return hashlib.sha256(b64u(entry["ed25519_public"]) + b64u(entry["mldsa65_public"])).hexdigest()[:16]


def dns_publication():
    """TXT records of _verifbox.internetidentitycard.com, via DNS-over-HTTPS, with the DNSSEC 'AD' flag."""
    with urllib.request.urlopen(DOH_URL, timeout=15) as r:
        data = json.load(r)
    values = [a["data"].strip('"') for a in data.get("Answer", []) if a.get("type") == 16]
    return values, bool(data.get("AD"))


def parse_time(s): return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_keys(path):
    if path:
        raw = open(path, "rb").read(); origin = path
    else:
        with urllib.request.urlopen(KEYS_URL, timeout=15) as r:
            raw = r.read(); origin = KEYS_URL
    data = json.loads(raw)
    entries = data["cles"] if isinstance(data.get("cles"), list) else [data]
    keys = {e["cle"]: dict(e) for e in entries if all(k in e for k in ("cle", "ed25519_public", "mldsa65_public"))}
    return keys, origin, hashlib.sha256(raw).hexdigest()


def trusted(key, keys, roots, seen=None):
    """A key without attestation is trusted only if it is a pinned root (full public-key hash);
    an attested key must be signed by a trusted, non-revoked previous key over the transition message."""
    seen = seen or set()
    if "attestation" not in key: return roots.get(key["cle"]) == full_key_hash(key)
    a = key["attestation"]; old = keys.get(a.get("par"))
    if old is None or key["cle"] in seen or old.get("statut") == "revoquee": return False
    # The attestation must be dated within the validity period of the attesting key.
    try:
        d = parse_time(a["date"])
        if (old.get("valide_depuis") and d < parse_time(old["valide_depuis"])) or (old.get("valide_jusqu") and d > parse_time(old["valide_jusqu"])):
            return False
    except Exception:
        return False
    content = {"ancienne": a["par"], "nouvelle": key["cle"], "date": a["date"],
               "ed25519_public": key["ed25519_public"], "mldsa65_public": key["mldsa65_public"]}
    ed, pq = signatures_ok(TRANSITION_PREFIX + canonical(content), a, old)
    return ed and pq and trusted(old, keys, roots, seen | {key["cle"]})


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""): h.update(block)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser(description="Independent verifier for VerifBox proofs.")
    p.add_argument("proof"); p.add_argument("file", nargs="?")
    p.add_argument("--keys", help="local public key file (otherwise downloaded from verifbox.com)")
    p.add_argument("--ots", help="write the Bitcoin anchor to this .ots file, for 'ots verify'")
    p.add_argument("--offline", action="store_true", help="no network access (requires --keys); skips the DNS cross-check")
    p.add_argument("--root", action="append", default=[], metavar="KEYID:SHA256",
                   help="trust an additional root key, given by its identifier and full public-key SHA-256")
    a = p.parse_args()
    ok, lines = True, []
    def check(passed, text):
        nonlocal ok
        lines.append(("PASS" if passed is True else "FAIL" if passed is False else "NOTE", text))
        if passed is False: ok = False

    roots = dict(PINNED_ROOTS)
    for r in a.root:
        kid, _, h = r.partition(":"); roots[kid] = h.lower()
    try:
        import os
        if os.path.getsize(a.proof) > MAX_PROOF_SIZE: raise ValueError("proof file too large (1 MB maximum)")
        proof = json.load(open(a.proof))
        c, s = proof["contenu"], proof["signatures"]
        if c.get("format") != "verifbox-preuve-1": raise ValueError(f"unsupported proof format: {c.get('format')}")
        if a.offline and not a.keys: raise ValueError("--offline requires --keys")
        keys, origin, keys_hash = load_keys(a.keys)
    except Exception as e:
        print(f"ERROR: {e}"); return 2

    print(f"Public keys: {origin}\n  SHA-256 of the key file: {keys_hash}")
    bad = check_schema(proof)
    if bad:
        # Malformed proof: stop here, before any function that assumes a correct structure.
        print("\n  [FAIL] Invalid proof format: " + ", ".join(bad))
        print("\nRESULT: NOT VALID")
        return 1
    # Independent publication of the key file fingerprint (root of trust outside verifbox.com).
    if a.offline:
        check(None, f"Offline: compare the key file SHA-256 above with the TXT record {DNS_NAME} yourself.")
    else:
        try:
            values, dnssec = dns_publication()
            published = [v for v in values if f"sha256={keys_hash}" in v.split()]
            if published and dnssec: check(True, f"Key file matches its independent publication ({DNS_NAME}, DNSSEC-validated)")
            elif published: check(None, f"Key file matches {DNS_NAME}, but the DNSSEC validation flag was not returned")
            else: check(False, f"Key file does NOT match its publication in {DNS_NAME}: {values or 'no record'}")
        except Exception as e:
            check(None, f"DNS cross-check unavailable ({e.__class__.__name__}); compare with {DNS_NAME} yourself.")
    for kid, entry in list(keys.items()):
        if key_id(entry) != kid:
            check(False, f"Key {kid}: identifier does not match its public keys (SHA-256 recomputed)")
            del keys[kid]
    key = keys.get(c["cle"])
    if key is None:
        check(False, f"Signing key {c['cle']} is not in the public key file.")
    else:
        ed, pq = signatures_ok(PROOF_PREFIX + canonical(c), s, key)
        check(ed, "Ed25519 signature"); check(pq, "ML-DSA-65 (FIPS 204) signature")
        t = parse_time(c["horodatage"])
        check(trusted(key, keys, roots), f"Key {key['cle']}: trusted (pinned root or attested by a trusted key)")
        # Validity starts at the later of valide_depuis and the SIGNED attestation date.
        starts = [x for x in (key.get("valide_depuis"), (key.get("attestation") or {}).get("date")) if x]
        if starts:
            start = max(starts, key=parse_time)
            check(t >= parse_time(start), f"Proof dated after the key was put into service ({start})")
        if key.get("valide_jusqu"): check(t <= parse_time(key["valide_jusqu"]), f"Proof dated before the key was retired ({key['valide_jusqu']})")
        if key.get("statut") == "revoquee":
            check(None, f"Key REVOKED on {key.get('revoquee_le')}: the proof is only reliable if its Bitcoin anchor "
                        "(checked with 'ots verify') is in a block dated before the revocation.")
            ok = False

    if a.file:
        check(file_sha256(a.file) == c["empreinte"], f"File fingerprint matches ({c['empreinte']})")
    else:
        check(None, "Original file not provided: its fingerprint was not checked.")

    ots_b64 = (proof.get("ancrages") or {}).get("bitcoin", {}).get("ots")
    if ots_b64:
        ots = base64.b64decode(ots_b64)
        same = ots.startswith(OTS_MAGIC) and ots[31] == 1 and ots[32] == 0x08 and ots[33:65].hex() == c["empreinte"]
        check(same, "The embedded Bitcoin anchor refers to this fingerprint (structural check; verify it against Bitcoin with 'ots verify')")
        if a.ots:
            open(a.ots, "wb").write(ots)
            check(None, f"Anchor written to {a.ots}: run  ots verify {a.ots}  (with the original file alongside)")
        else:
            check(None, "Bitcoin anchor present: use --ots FILE.ots, then 'ots verify' to check it against Bitcoin.")
    else:
        check(None, "No Bitcoin anchor in this proof.")

    print(f"\nProof {c['identifiant']}  |  timestamp {c['horodatage']}  |  key {c['cle']}")
    for status, text in lines: print(f"  [{status}] {text}")
    print("\nRESULT: " + ("VALID (signatures and file)" if ok else "NOT VALID"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
