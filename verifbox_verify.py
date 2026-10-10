#!/usr/bin/env python3
"""
verifbox_verify.py - Independent verifier for VerifBox timestamp proofs (format verifbox-preuve-1).

Checks, without contacting the VerifBox service:
  - the file's SHA-256 fingerprint against the proof,
  - the Ed25519 and ML-DSA-65 (FIPS 204) signatures,
  - the signing key: identifier, attestation chain, validity period, revocation status,
  - the public key file against its independent publication in the DNS of
    internetidentitycard.com (TXT record _verifbox, DNSSEC-validated), unless --offline,
  - the IIC TSA time-stamp token (RFC 3161), when the proof carries one: status, file
    fingerprint, policy, signed attributes, ECDSA signature, certificate issued by a PINNED
    IIC TSA root, time-stamping usage, validity and revocation (root CRL).
The Bitcoin anchor is checked separately with the official OpenTimestamps client:
  this tool extracts the .ots file for that purpose (--ots).

Install:   pip install cryptography dilithium-py
Usage:     python3 verifbox_verify.py PROOF.verifbox.json [ORIGINAL_FILE] [--keys verifbox-cles.json] [--ots OUT.ots] [--offline]
                                     [--root KEYID:SHA256] [--tsr OUT.tsr] [--iic-root ROOT.pem --iic-crl ROOT.crl]
                                     [--iic-root-sha256 SHA256]

Trust: the root key is PINNED in this file by the SHA-256 of its two public keys (PINNED_ROOTS). A key file
can only add keys that are attested by a trusted key; an unknown root key is rejected.

Without --keys, the public keys are downloaded from https://verifbox.com/.well-known/verifbox-cles.json
and their SHA-256 fingerprint is printed, so you can compare it with independent publications.
Specification: https://verifbox.com/specification
Exit code: 0 = valid, 1 = invalid, 2 = error.  Licence: MIT.
"""
import argparse, base64, hashlib, json, sys, urllib.parse, urllib.request
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
ATTESTATION_PREFIX = b"verifbox-attestation-v1\n"
# Trusted root keys: identifier -> SHA-256(Ed25519 public key || ML-DSA-65 public key), full 256 bits.
PINNED_ROOTS = {"258e57366bcdb6ce": "258e57366bcdb6ce16cc22fe972c638346de2a5415327154a030e5a6b9293946"}
MAX_PROOF_SIZE = 1 << 20
# IIC TSA: trusted root certificates, by SHA-256 of their DER encoding.
PINNED_IIC_TSA_ROOTS = {"8652e3d13e725f7c757cfa053d641360aca443cf6c09d7d6ddd44bea851ed3b9": "IIC TSA Root R1 (production, offline ceremony of 10 October 2026)"}
IIC_TSA_POLICIES = ["1.3.6.1.4.1.67100.1.1.1.1"]
IIC_TSA_TEST_POLICY = "1.3.6.1.4.1.67100.1.1.9.1"
IIC_TSA_TRUST_URL = "https://verifbox.com/.well-known/iic-tsa.json"
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


def attestation_digest(content, sigs):
    """Digest of the signed attestation, anchored in Bitcoin as the second anchor (specification, section 7)."""
    return hashlib.sha256(ATTESTATION_PREFIX + canonical(content) + b"\n" + sigs["ed25519"].encode() + b"\n" + sigs["ml_dsa_65"].encode()).hexdigest()


def ots_digest(ots):
    return ots[33:65].hex() if ots.startswith(OTS_MAGIC) and ots[31] == 1 and ots[32] == 0x08 else None


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


# ---------------------------------------------------------------- IIC TSA token (RFC 3161 / RFC 5816)
def der(o, p=0):
    """(tag, content start, end) of the DER element at p; strict lengths."""
    tag, n, h = o[p], o[p + 1], 2
    if n & 0x80:
        k = n & 0x7F
        if not 1 <= k <= 3: raise ValueError("der")
        n, h = int.from_bytes(o[p + 2:p + 2 + k], "big"), 2 + k
    if p + h + n > len(o): raise ValueError("der")
    return tag, p + h, p + h + n


def kids(o, node, tag=None):
    t, a, b = node
    if tag is not None and t != tag: raise ValueError("structure")
    out, p = [], a
    while p < b:
        e = der(o, p)
        if e[2] > b: raise ValueError("der")
        out.append((e, p)); p = e[2]
    if p != b: raise ValueError("der")
    return out


def oid_of(o, node):
    t, a, b = node
    if t != 6: raise ValueError("oid")
    c = o[a:b]; r = [c[0] // 40, c[0] % 40]; v = 0
    for x in c[1:]:
        v = v * 128 + (x & 0x7F)
        if not x & 0x80: r.append(v); v = 0
    return ".".join(map(str, r))


def gen_time(o, node):
    t, a, b = node
    if t != 0x18: raise ValueError("date")
    from datetime import timezone
    s = o[a:b].decode()
    frac = s[14:-1]
    d = datetime.strptime(s[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    return d.replace(microsecond=int(round(float("0" + frac) * 1e6)) if frac else 0)


def verify_iic_token(tsr, fingerprint, roots, policies, crl_der=None):
    """Full check of an IIC TSA TimeStampResp. roots: list of (DER, is_test). Raises ValueError(reason)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    o = tsr
    top = der(o)
    if top[0] != 0x30 or top[2] != len(o): raise ValueError("response")
    resp = kids(o, top, 0x30)
    if len(resp) != 2: raise ValueError("response")
    status = kids(o, resp[0][0], 0x30)[0][0]
    if int.from_bytes(o[status[1]:status[2]], "big") not in (0, 1): raise ValueError("refused")
    ci = kids(o, resp[1][0], 0x30)
    if len(ci) != 2 or oid_of(o, ci[0][0]) != "1.2.840.113549.1.7.2" or ci[1][0][0] != 0xA0: raise ValueError("signed-data")
    sd = kids(o, kids(o, ci[1][0])[0][0], 0x30)
    if o[sd[0][0][1]:sd[0][0][2]] != b"\x03": raise ValueError("signed-data")
    encap = kids(o, sd[2][0], 0x30)
    if oid_of(o, encap[0][0]) != "1.2.840.113549.1.9.16.1.4": raise ValueError("tst-info")
    octets = kids(o, encap[1][0])[0][0]
    if octets[0] != 0x04: raise ValueError("tst-info")
    tst_der = o[octets[1]:octets[2]]
    tst = kids(tst_der, der(tst_der), 0x30)
    policy = oid_of(tst_der, tst[1][0])
    mi = kids(tst_der, tst[2][0], 0x30)
    if oid_of(tst_der, kids(tst_der, mi[0][0], 0x30)[0][0]) != "2.16.840.1.101.3.4.2.1": raise ValueError("hash algorithm")
    if tst_der[mi[1][0][1]:mi[1][0][2]].hex() != fingerprint: raise ValueError("fingerprint")
    if policy not in policies: raise ValueError("policy " + policy)
    serial = int.from_bytes(tst_der[tst[3][0][1]:tst[3][0][2]], "big")
    when = gen_time(tst_der, tst[4][0])
    accuracy = None
    acc = next((e for e, _ in tst[5:] if e[0] == 0x30), None)
    if acc:
        accuracy = 0.0
        for e, _ in kids(tst_der, acc):
            v = int.from_bytes(tst_der[e[1]:e[2]], "big")
            accuracy += {0x02: v, 0x80: v / 1e3, 0x81: v / 1e6}.get(e[0], 0)
    certs = [o[p:e[2]] for node, _ in sd if node[0] == 0xA0 for e, p in kids(o, node) if e[0] == 0x30]
    infos = kids(o, sd[-1][0], 0x31)
    if len(infos) != 1: raise ValueError("signer-info")
    si = kids(o, infos[0][0], 0x30)
    attrs_node, attrs_pos = next(((e, p) for e, p in si if e[0] == 0xA0), (None, None))
    if attrs_node is None: raise ValueError("signed attributes")
    attrs = {}
    for e, _ in kids(o, attrs_node):
        t, v = [x for x, _ in kids(o, e, 0x30)]
        vals = kids(o, v, 0x31)
        if len(vals) != 1: raise ValueError("signed attributes")
        attrs[oid_of(o, t)] = vals[0][0]
    ct = attrs.get("1.2.840.113549.1.9.3"); md = attrs.get("1.2.840.113549.1.9.4"); scv2 = attrs.get("1.2.840.113549.1.9.16.2.47")
    if ct is None or oid_of(o, ct) != "1.2.840.113549.1.9.16.1.4": raise ValueError("content-type")
    if md is None or o[md[1]:md[2]] != hashlib.sha256(tst_der).digest(): raise ValueError("message-digest")
    if scv2 is None: raise ValueError("signing-certificate-v2")
    ess = [x for x, _ in kids(o, kids(o, kids(o, scv2, 0x30)[0][0], 0x30)[0][0], 0x30)]
    k = 0
    if ess[0][0] == 0x30:
        if oid_of(o, kids(o, ess[0], 0x30)[0][0]) != "2.16.840.1.101.3.4.2.1": raise ValueError("ESSCertIDv2")
        k = 1
    cert_hash = o[ess[k][1]:ess[k][2]]
    leaf_der = next((c for c in certs if hashlib.sha256(c).digest() == cert_hash), None)
    if leaf_der is None: raise ValueError("signer certificate")
    leaf = x509.load_der_x509_certificate(leaf_der)
    i = [e for e, _ in si].index(attrs_node)
    sig_alg, sig = si[i + 1][0], si[i + 2][0]
    if oid_of(o, kids(o, sig_alg, 0x30)[0][0]) != "1.2.840.10045.4.3.2" or sig[0] != 0x04: raise ValueError("signature algorithm")
    sid = kids(o, si[1][0], 0x30)
    if o[sid[0][1]:sid[0][0][2]] != leaf.issuer.public_bytes() or int.from_bytes(o[sid[1][0][1]:sid[1][0][2]], "big") != leaf.serial_number:
        raise ValueError("signer identifier")
    signed = b"\x31" + o[attrs_pos + 1:attrs_node[2]]
    try:
        leaf.public_key().verify(o[sig[1]:sig[2]], signed, ec.ECDSA(hashes.SHA256()))
    except Exception:
        raise ValueError("signature")
    root, test = None, False
    for rder, is_test in roots:
        r = x509.load_der_x509_certificate(rder)
        if r.subject == leaf.issuer:
            try:
                r.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
                root, test = r, is_test
            except Exception:
                pass
    if root is None: raise ValueError("unknown root")
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if not eku.critical or [u.dotted_string for u in eku.value] != ["1.3.6.1.5.5.7.3.8"]: raise ValueError("certificate usage")
    except x509.ExtensionNotFound:
        raise ValueError("certificate usage")
    if not leaf.not_valid_before_utc <= when <= leaf.not_valid_after_utc: raise ValueError("certificate not valid at token time")
    revocation = "not checked"
    if crl_der:
        crl = x509.load_der_x509_crl(crl_der)
        if crl.issuer != root.subject or not crl.is_signature_valid(root.public_key()): raise ValueError("crl")
        entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
        if entry is not None:
            try: cutoff = entry.extensions.get_extension_for_class(x509.InvalidityDate).value.invalidity_date_utc
            except x509.ExtensionNotFound: cutoff = entry.revocation_date_utc
            if when >= cutoff: raise ValueError("certificate revoked")
            revocation = f"certificate revoked on {cutoff.isoformat()}, after this token"
        else:
            nu = crl.next_update_utc
            revocation = "not revoked" + (" (revocation list out of date)" if nu and nu < datetime.now(when.tzinfo) else "")
    return {"time": when, "accuracy": accuracy, "serial": "%x" % serial, "policy": policy, "test": test, "revocation": revocation}


def pem_to_der(data):
    if b"-----BEGIN" in data:
        return base64.b64decode(b"".join(l for l in data.splitlines() if l and not l.startswith(b"-----")))
    return data


def main():
    p = argparse.ArgumentParser(description="Independent verifier for VerifBox proofs.")
    p.add_argument("proof"); p.add_argument("file", nargs="?")
    p.add_argument("--keys", help="local public key file (otherwise downloaded from verifbox.com)")
    p.add_argument("--ots", help="write the Bitcoin anchor of the file to this .ots file, for 'ots verify'")
    p.add_argument("--ots-attestation", help="write the Bitcoin anchor of the attestation to this .ots file")
    p.add_argument("--offline", action="store_true", help="no network access (requires --keys); skips the DNS cross-check")
    p.add_argument("--root", action="append", default=[], metavar="KEYID:SHA256",
                   help="trust an additional root key, given by its identifier and full public-key SHA-256")
    p.add_argument("--tsr", help="write the IIC TSA time-stamp token to this .tsr file, for 'openssl ts -verify'")
    p.add_argument("--iic-root", help="IIC TSA root certificate (PEM or DER) instead of downloading it")
    p.add_argument("--iic-crl", help="IIC TSA root CRL (DER) instead of downloading it")
    p.add_argument("--iic-root-sha256", action="append", default=[], metavar="SHA256",
                   help="trust an additional IIC TSA root certificate, given by the SHA-256 of its DER encoding")
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
        if not isinstance(proof, dict): proof = {}           # rejected below by the strict format check
        c = proof.get("contenu") if isinstance(proof.get("contenu"), dict) else {}
        s = proof.get("signatures") if isinstance(proof.get("signatures"), dict) else {}
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
            has_att = bool(((proof.get("ancrages") or {}).get("attestation") or {}).get("ots"))
            check(None, f"Key REVOKED on {key.get('revoquee_le')}: " + (
                "the proof is only reliable if the Bitcoin anchor of its ATTESTATION is in a block dated before the revocation "
                "(extract it with --ots-attestation and check it with 'ots verify -d <attestation digest>')." if has_att else
                "this proof has no anchor of its attestation, so its signed date can no longer be relied upon; at most, the "
                "anchor of the file shows that the file existed before its block."))
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
    # Second anchor: the signed attestation itself.
    att_b64 = ((proof.get("ancrages") or {}).get("attestation") or {}).get("ots")
    if att_b64:
        try:
            att = base64.b64decode(att_b64); expected = attestation_digest(c, s)
            same = ots_digest(att) == expected
        except Exception:
            same, att, expected = False, None, None
        check(same, f"The embedded anchor of the attestation refers to this attestation (structural check; digest {expected})")
        if same and a.ots_attestation:
            open(a.ots_attestation, "wb").write(att)
            check(None, f"Attestation anchor written to {a.ots_attestation}: run  ots verify -d {expected} {a.ots_attestation}")
    else:
        check(None, "No anchor of the attestation (proof issued before the two-anchor format).")

    # IIC TSA time-stamp token (RFC 3161), over the file fingerprint.
    token = (proof.get("jetons") or {}).get("iic_tsa")
    if token:
        try:
            tsr = base64.b64decode(token.get("tsr", ""), validate=True)
            pins = {**PINNED_IIC_TSA_ROOTS, **{h.lower(): "command line" for h in a.iic_root_sha256}}
            crl = open(a.iic_crl, "rb").read() if a.iic_crl else None
            if a.iic_root:
                candidates = [pem_to_der(open(a.iic_root, "rb").read())]
            elif a.offline:
                candidates = []
            else:
                with urllib.request.urlopen(IIC_TSA_TRUST_URL, timeout=15) as r:
                    trust = json.load(r)
                candidates = [base64.b64decode(x["certificat"]) for x in trust.get("racines", [])]
                if crl is None and trust.get("crl"):
                    with urllib.request.urlopen(urllib.parse.urljoin(IIC_TSA_TRUST_URL, trust["crl"]), timeout=15) as r:
                        crl = r.read()
            roots = [(d, hashlib.sha256(d).hexdigest() not in PINNED_IIC_TSA_ROOTS) for d in candidates
                     if hashlib.sha256(d).hexdigest() in pins]
            if not roots:
                check(None, "IIC TSA time-stamp token present, but no pinned IIC TSA root is available: not checked "
                            "(give --iic-root and --iic-root-sha256, or use a verifier version with the production root pinned).")
            else:
                r = verify_iic_token(tsr, c["empreinte"], roots, IIC_TSA_POLICIES + [IIC_TSA_TEST_POLICY])
                if crl is not None:
                    r = verify_iic_token(tsr, c["empreinte"], roots, IIC_TSA_POLICIES + [IIC_TSA_TEST_POLICY], crl)
                label = "IIC TSA TEST token (test service, not a production proof)" if r["policy"] == IIC_TSA_TEST_POLICY else "IIC TSA time-stamp token (RFC 3161)"
                acc = f", accuracy +/- {r['accuracy']:g} s" if r["accuracy"] is not None else ""
                check(True if r["policy"] != IIC_TSA_TEST_POLICY else None,
                      f"{label}: {r['time'].strftime('%Y-%m-%d %H:%M:%S')} UTC{acc}, serial {r['serial']}, revocation: {r['revocation']}")
                gap = abs((r["time"] - parse_time(c["horodatage"])).total_seconds())
                if gap > 10: check(None, f"The token time differs from the signed time by {gap:.0f} s")
        except ValueError as e:
            check(False, f"IIC TSA time-stamp token INVALID ({e})")
        except Exception as e:
            check(None, f"IIC TSA time-stamp token could not be checked ({e.__class__.__name__})")
        if a.tsr and token.get("tsr"):
            open(a.tsr, "wb").write(base64.b64decode(token["tsr"]))
            check(None, f"Token written to {a.tsr}: openssl ts -verify -in {a.tsr} -data ORIGINAL_FILE -CAfile IIC_TSA_ROOT.pem")

    print(f"\nProof {c['identifiant']}  |  timestamp {c['horodatage']}  |  key {c['cle']}")
    for status, text in lines: print(f"  [{status}] {text}")
    if not ok: verdict = "NOT VALID"
    elif a.file: verdict = "VALID (signatures and file)"
    else: verdict = "VALID SIGNATURES (original file not checked: provide it to confirm the fingerprint)"
    print("\nRESULT: " + verdict)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
