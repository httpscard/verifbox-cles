#!/usr/bin/env python3
"""
verifbox_verify.py - Independent verifier for VerifBox timestamp proofs (format verifbox-preuve-1).

Checks, without contacting the VerifBox API (the key file is fetched from verifbox.com unless --keys or --offline is given):
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
                                     [--iic-root-sha256 SHA256] [--bundle FOLDER.zip [--bundle-include-file]]
  --bundle writes a proof folder (.zip): every element needed to examine the proof without VerifBox, a report,
  a README with the commands, and MANIFEST.sha256. It adds no signature (specification, section 12).

Trust: the root key is PINNED in this file by the SHA-256 of its two public keys (PINNED_ROOTS). A key file
can only add keys that are attested by a trusted key; an unknown root key is rejected.

Without --keys, the public keys are downloaded from https://verifbox.com/.well-known/verifbox-cles.json
and their SHA-256 fingerprint is printed, so you can compare it with independent publications.
Specification: https://verifbox.com/specification
Exit code: 0 = valid, 1 = invalid, 2 = error.  Licence: MIT.
"""
import argparse, base64, hashlib, json, os, re, shutil, subprocess, sys, tempfile, urllib.parse, urllib.request
from datetime import datetime, timezone

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


def explorers_merkle_root(height):
    """Merkle root of a Bitcoin block according to two independent public explorers; {} if none answers."""
    found = {}
    for name, base in (("blockstream.info", "https://blockstream.info/api"), ("mempool.space", "https://mempool.space/api")):
        try:
            with urllib.request.urlopen(f"{base}/block-height/{height}", timeout=15) as r: block_hash = r.read().decode().strip()
            with urllib.request.urlopen(f"{base}/block/{block_hash}", timeout=15) as r: found[name] = json.load(r)["merkle_root"]
        except Exception:
            pass
    return found


def ots_block_check(ots_bytes, label, check, file=None, digest=None):
    """Walk an OpenTimestamps proof with the ots client (no Bitcoin node needed), then compare the merkle root it
    commits to with two independent public block explorers. Reports PASS / FAIL / NOTE through check()."""
    with tempfile.NamedTemporaryFile(suffix=".ots", delete=False) as tmp:
        tmp.write(ots_bytes); tmp_path = tmp.name
    try:
        target = ["-f", file] if file else ["-d", digest]
        r = subprocess.run(["ots", "--no-bitcoin", "verify"] + target + [tmp_path], capture_output=True, text=True, timeout=120)
        out = (r.stdout + r.stderr).strip()
        m = re.search(r"block (\d+) has merkleroot ([0-9a-f]{64})", out)
        if m:
            height, root = int(m.group(1)), m.group(2)
            agree = explorers_merkle_root(height)
            if agree and all(v == root for v in agree.values()):
                check(True, f"{label} confirmed: block {height}, merkle root {root[:16]}... matches " + " and ".join(agree))
                return height
            elif agree:
                check(False, f"{label} does NOT match block {height}: merkle root {root} vs " + ", ".join(f"{k}: {v}" for k, v in agree.items()))
            else:
                check(None, f"{label} commits to block {height} (merkle root {root}); no block explorer reachable to confirm it. "
                            f"Check that block {height} has this merkle root, or run 'ots verify' with a Bitcoin node.")
        elif "pending" in out.lower():
            check(None, f"{label} pending: not yet in a block (come back later and load the completed proof).")
        else:
            check(None, f"{label}: ots verify did not establish a block: " + out.replace("\n", " | "))
    except Exception as e:
        check(None, f"{label}: ots verify could not run ({e.__class__.__name__})")
    finally:
        os.unlink(tmp_path)


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
    return keys, origin, hashlib.sha256(raw).hexdigest(), raw


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


BUNDLE_FORMAT = "verifbox-dossier-1"
GITHUB_URL = "https://github.com/httpscard/verifbox-cles"


def bundle_readme(r, en):
    """README.txt (en) / LISEZ-MOI.txt (fr) of a proof folder; same text as the web verifier's (js/dossier.js)."""
    f, a = r["fingerprint"], r["attestation_digest"]
    orig = ("original/" + r["original_file_name"]) if r["original_file_included"] else ("ORIGINAL_FILE" if en else "FICHIER_ORIGINAL")
    L = BUNDLE_TEXT["en" if en else "fr"]
    intro = L["intro"].format(id=r["proof_id"], t=r["signed_time"], f=f)
    hl = OFFLINE_PAGE_TEXT["en" if en else "fr"]
    out = [L["t"], "=" * len(L["t"]), "", intro, "", hl[0], "-" * len(hl[0]), *hl[1:], "", L["files"], "-" * len(L["files"])]
    out += [f"  {n:<28} {d}" for n, d in r["contents"]]
    out += ["", L["steps"], "-" * len(L["steps"]),
            f"0. {L['s0']}", "   sha256sum -c MANIFEST.sha256        (macOS: shasum -a 256 -c MANIFEST.sha256)", "",
            f"1. {L['s1']}", f"   {GITHUB_URL}/blob/main/verifbox_verify.py", "   pip install cryptography dilithium-py opentimestamps-client",
            f"   python3 verifbox_verify.py proof.verifbox.json {orig} --keys verifbox-keys.json --offline" + (" \\" if r["token"] else "")]
    if r["token"]: out.append("           --iic-root iic-tsa-root.pem --iic-crl iic-tsa-root.crl")
    out += ["", L["node1"], L["node2"], ""]
    if r["anchors"]["file"]: out += [f"2. {L['s2']}", f"   ots verify -f {orig} file-anchor.ots", f"   ots verify -d {f} file-anchor.ots", ""]
    if r["anchors"]["attestation"]: out += [f"3. {L['s3']}", f"   ots verify -d {a} attestation-anchor.ots", L["digest"], ""]
    if r["token"]: out += [f"4. {L['s4']}", "   openssl ts -reply -in iic-tsa-token.tsr -text",
                           f"   openssl ts -verify -in iic-tsa-token.tsr -digest {f} -CAfile iic-tsa-root.pem", ""]
    out += [f"5. {L['s5']}", "   ots verify -f verifbox-keys.json verifbox-keys.json.ots", f"   {GITHUB_URL}", "",
            L["trust"], "-" * len(L["trust"]), f"- {L['t1']}", f"- {L['t2']}", f"- {L['t3']}", f"- {L['t4']}", "",
            f"{L['spec']}: https://verifbox.com/specification", ""]
    return "\n".join(out)


# Offline verification page: SHA-256 of the published version (update after each regeneration, see outils/construire_hors_ligne.py).
OFFLINE_PAGE_SHA256 = "876bc3a95a224f8641abd340d1cc40ab9584c2d73c4f8173717fe553ba58a867"
OFFLINE_PAGE_TEXT = {"en": ["Without technical skills", "This folder contains no program and no script (apart from your own file in original/, if you chose to include it).", "To check the proof by double-click, download the offline verification page from the public repository or from its archive:", "  https://github.com/httpscard/verifbox-cles/blob/main/verifbox-verify-offline.html", "  https://archive.softwareheritage.org/browse/origin/?origin_url=https://github.com/httpscard/verifbox-cles", "Check its SHA-256 (version published when this folder was made):", "  876bc3a95a224f8641abd340d1cc40ab9584c2d73c4f8173717fe553ba58a867", "then open it in any browser (it works offline and makes no network request) and drop proof.verifbox.json and the original file onto it.", "It checks both signatures, the signing key and the file. It cannot confirm the Bitcoin anchors offline: see steps 2 and 3 below.", "If the repository now holds a newer version (for example after a key rotation), earlier versions remain in its history and in the Software Heritage archive."],
                     "fr": ["Sans compétence technique", "Ce dossier ne contient aucun programme ni script (hormis votre propre fichier dans original/, si vous avez choisi de l'inclure).", "Pour vérifier la preuve d'un double-clic, téléchargez la page de vérification hors ligne depuis le dépôt public ou son archive :", "  https://github.com/httpscard/verifbox-cles/blob/main/verifbox-verify-offline.html", "  https://archive.softwareheritage.org/browse/origin/?origin_url=https://github.com/httpscard/verifbox-cles", "Contrôlez son empreinte SHA-256 (version publiée à la création de ce dossier) :", "  876bc3a95a224f8641abd340d1cc40ab9584c2d73c4f8173717fe553ba58a867", "puis ouvrez-la dans n'importe quel navigateur (elle fonctionne sans connexion et ne fait aucune requête réseau) et déposez-y proof.verifbox.json et le fichier d'origine.", "Elle vérifie les deux signatures, la clé de signature et le fichier. Elle ne peut pas confirmer les ancrages Bitcoin hors ligne : voir les étapes 2 et 3 ci-dessous.", "Si le dépôt contient aujourd'hui une version plus récente (par exemple après une rotation de clé), les versions antérieures restent dans son historique et dans l'archive Software Heritage."]}

BUNDLE_TEXT = {
 "en": dict(t="VerifBox proof folder", files="Contents", steps="How to check it yourself", trust="Where trust comes from", spec="Format specification",
   intro="Proof {id}, signed time {t} UTC, file fingerprint (SHA-256):\n  {f}\n\nThis folder lets anyone examine the proof without the VerifBox website. It adds no signature: each element below proves itself, and MANIFEST.sha256 only checks that no file of the folder was altered.",
   s0="Integrity of the folder", s1="Signatures, key and IIC TSA token, offline (independent verifier, MIT licence)",
   s2="Bitcoin anchor of the file (OpenTimestamps client)", s3="Bitcoin anchor of the signed attestation", s4="RFC 3161 token, with OpenSSL only",
   s5="Public key file: its own Bitcoin anchor, and its independent publications",
   node1='   (verifbox_verify.py checks each Bitcoin block against two public explorers. "ots verify" below needs a local',
   node2="    Bitcoin node; without one, add --no-bitcoin and compare the block and merkle root it prints with any explorer.)",
   digest='   (digest = SHA-256 of "verifbox-attestation-v1\\n" + canonical content + "\\n" + Ed25519 sig + "\\n" + ML-DSA-65 sig; see attestation.json)',
   t1="The Bitcoin anchors are the only elements that do not depend on the operator: they show that the file and the signed attestation existed no later than their blocks.",
   t2="IIC TSA is operated by HTTPS CARD - Internet Identity Card Limited, the company that publishes VerifBox: it is not an independent third party. It is not a qualified trust service (Regulation (EU) No 910/2014). Its token is checked against the IIC TSA Root R1, SHA-256 8652e3d13e725f7c757cfa053d641360aca443cf6c09d7d6ddd44bea851ed3b9 (published on tsa.internetidentitycard.com and in the Practice Statement).",
   t3="Compare the SHA-256 of verifbox-keys.json with the DNS TXT record _verifbox.internetidentitycard.com (DNSSEC) and with GitHub.",
   t4="verification-report.txt records what a verifier found when this folder was made. It is a record, not evidence: run the checks again."),
 "fr": dict(t="Dossier de preuve VerifBox", files="Contenu", steps="Comment le vérifier soi-même", trust="D'où vient la confiance", spec="Spécification du format",
   intro="Preuve {id}, heure signée {t} UTC, empreinte du fichier (SHA-256) :\n  {f}\n\nCe dossier permet à quiconque d'examiner la preuve sans le site VerifBox. Il n'ajoute aucune signature : chaque élément ci-dessous se prouve lui-même, et MANIFEST.sha256 vérifie seulement qu'aucun fichier du dossier n'a été modifié.",
   s0="Intégrité du dossier", s1="Signatures, clé et jeton IIC TSA, hors ligne (vérificateur indépendant, licence MIT)",
   s2="Ancrage Bitcoin du fichier (client OpenTimestamps)", s3="Ancrage Bitcoin de l'attestation signée", s4="Jeton RFC 3161, avec OpenSSL seul",
   s5="Fichier des clés publiques : son propre ancrage Bitcoin et ses publications indépendantes",
   node1='   (verifbox_verify.py contrôle chaque bloc Bitcoin auprès de deux explorateurs publics. "ots verify" ci-dessous',
   node2="    demande un nœud Bitcoin local ; sans nœud, ajoutez --no-bitcoin et comparez le bloc et la racine de Merkle affichés avec un explorateur.)",
   digest='   (empreinte = SHA-256 de "verifbox-attestation-v1\\n" + contenu canonique + "\\n" + signature Ed25519 + "\\n" + signature ML-DSA-65 ; voir attestation.json)',
   t1="Les ancrages Bitcoin sont les seuls éléments qui ne dépendent pas de l'exploitant : ils montrent que le fichier et l'attestation signée existaient au plus tard à leur bloc.",
   t2="IIC TSA est exploité par HTTPS CARD - Internet Identity Card Limited, la société qui publie VerifBox : ce n'est pas un tiers indépendant. Ce n'est pas un service de confiance qualifié (règlement (UE) n° 910/2014). Son jeton est vérifié avec la racine IIC TSA Root R1, SHA-256 8652e3d13e725f7c757cfa053d641360aca443cf6c09d7d6ddd44bea851ed3b9 (publiée sur tsa.internetidentitycard.com et dans la Practice Statement).",
   t3="Comparez le SHA-256 de verifbox-keys.json avec l'enregistrement DNS TXT _verifbox.internetidentitycard.com (DNSSEC) et avec GitHub.",
   t4="verification-report.txt consigne ce qu'un vérificateur a constaté à la création du dossier. C'est un relevé, pas une preuve : refaites les contrôles."),
}


def write_bundle(path, proof, lines, verdict, keys_raw, keys_ots, iic, include_file, checked_file):
    """Proof folder (.zip): the elements of the proof, each verifiable on its own; MANIFEST.sha256 checks integrity only.
    Adds no signature. Same layout as the web verifier's 'Proof folder (.zip)' button."""
    import zipfile
    c, s = proof["contenu"], proof["signatures"]
    now = datetime.now(timezone.utc)
    files, contents = [], []
    def add(name, data, en, fr=None):
        files.append((name, data)); contents.append((name, en, fr or en))
    dump = lambda o: json.dumps(o, ensure_ascii=False, indent=2).encode() + b"\n"
    add("proof.verifbox.json", dump(proof), "the proof (anchors completed when possible; signed content unchanged)", "la preuve (ancrages complétés si possible ; contenu signé inchangé)")
    msg = PROOF_PREFIX + canonical(c)
    att = {"format": c["format"], "signed_content": c,
           "signed_message": 'UTF-8 of "verifbox-preuve-v1\\n" followed by the canonical JSON of signed_content (keys sorted, no spaces)',
           "signed_message_sha256": hashlib.sha256(msg).hexdigest(),
           "signatures": {"ed25519": s["ed25519"], "ml_dsa_65": s["ml_dsa_65"]},
           "algorithms": {"ed25519": "Ed25519 (RFC 8032), base64url", "ml_dsa_65": "ML-DSA-65 (FIPS 204), pure mode, empty context, base64url"},
           "key_id": c["cle"], "attestation_digest": attestation_digest(c, s)}
    add("attestation.json", dump(att), "signed content, signed message, both signatures and algorithms", "contenu signé, message signé, les deux signatures et leurs algorithmes")
    anc = proof.get("ancrages") or {}
    if (anc.get("bitcoin") or {}).get("ots"):
        add("file-anchor.ots", base64.b64decode(anc["bitcoin"]["ots"]), "OpenTimestamps anchor of the file fingerprint", "ancrage OpenTimestamps de l'empreinte du fichier")
    if (anc.get("attestation") or {}).get("ots"):
        add("attestation-anchor.ots", base64.b64decode(anc["attestation"]["ots"]), "OpenTimestamps anchor of the signed attestation", "ancrage OpenTimestamps de l'attestation signée")
    tok = (proof.get("jetons") or {}).get("iic_tsa")
    root_sha = None
    if tok and tok.get("tsr"):
        add("iic-tsa-token.tsr", base64.b64decode(tok["tsr"]), "IIC TSA RFC 3161 time-stamp response over the file fingerprint", "réponse d'horodatage RFC 3161 d'IIC TSA sur l'empreinte du fichier")
        if iic["root"]:
            root_sha = hashlib.sha256(iic["root"]).hexdigest()
            b64 = base64.b64encode(iic["root"]).decode()
            pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n-----END CERTIFICATE-----\n"
            add("iic-tsa-root.pem", pem.encode(), f"IIC TSA Root R1, SHA-256 (DER) {root_sha}")
        if iic["crl"]:
            add("iic-tsa-root.crl", iic["crl"], "IIC TSA root CRL (DER)", "liste de révocation de la racine IIC TSA (DER)")
        if iic["trust"]:
            add("iic-tsa-trust.json", iic["trust"], "IIC TSA trust file: roots, policy OID, CRL location", "fichier de confiance IIC TSA : racines, OID de politique, emplacement de la CRL")
    kh = hashlib.sha256(keys_raw).hexdigest()
    add("verifbox-keys.json", keys_raw, f"VerifBox public keys, SHA-256 {kh}", f"clés publiques VerifBox, SHA-256 {kh}")
    if keys_ots:
        add("verifbox-keys.json.ots", keys_ots, "OpenTimestamps anchor of the key file", "ancrage OpenTimestamps du fichier des clés")
    safe = None
    if include_file:
        safe = re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", os.path.basename(include_file)).lstrip(".")[:120] or "file"
        add("original/" + safe, open(include_file, "rb").read(), "the original file (included at the user’s request)", "le fichier d’origine (inclus à la demande de l’utilisateur)")
    def blk(x, confirmed):
        # block: the one this verifier confirmed against two explorers, else the one recorded in the proof (unsigned field).
        if not (x or {}).get("ots"): return None
        state = "complete" if (confirmed or x.get("etat") == "complet") else x.get("etat")
        return {k: v for k, v in (("state", state), ("block", confirmed or x.get("bloc")), ("block_time", x.get("date_bloc"))) if v is not None}
    t = iic["token"]
    summary = {"format": BUNDLE_FORMAT, "created": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
               "verifier": {"name": "verifbox_verify.py", "version": "sha256:" + hashlib.sha256(open(__file__, "rb").read()).hexdigest()},
               "proof_id": c["identifiant"], "proof_format": c["format"], "fingerprint": c["empreinte"], "hash_algorithm": c["algorithme"],
               "signed_time": c["horodatage"], "key_id": c["cle"],
               "original_file_name": safe or (proof.get("informatif") or {}).get("fichier") or (os.path.basename(checked_file) if checked_file else None),
               "original_file_included": bool(include_file), "attestation_digest": att["attestation_digest"],
               "anchors": {"file": blk(anc.get("bitcoin"), iic.get("file_block")), "attestation": blk(anc.get("attestation"), iic.get("att_block"))},
               "token": ({"issuer": "IIC TSA (same company as VerifBox)", "time": t["time"].isoformat().replace("+00:00", "Z") if t else tok.get("heure"),
                          "serial": t["serial"] if t else tok.get("serie"), "policy": t["policy"] if t else tok.get("politique"),
                          "root_sha256": root_sha, "revocation": t["revocation"] if t else None} if tok else None),
               "verdict": verdict}
    add("summary.json", dump(summary), "machine-readable summary: identifiers, UTC times, blocks, token", "résumé lisible par machine : identifiants, heures UTC, blocs, jeton")
    report = ["VerifBox verification report", "RECORD ONLY, NOT AN ELEMENT OF PROOF: run the checks again (README.txt).",
              f"Verifier: verifbox_verify.py, {summary['verifier']['version']}", f"Checked at: {summary['created']}",
              f"Proof: {c['identifiant']}  |  {c['horodatage']}  |  key {c['cle']}", ""] + [f"  [{st}] {tx}" for st, tx in lines] + ["", f"RESULT: {verdict}", ""]
    add("verification-report.txt", "\n".join(report).encode(), "what this verifier found when the folder was made (record only)", "ce que ce vérificateur a constaté à la création du dossier (relevé seulement)")
    contents += [("README.txt / LISEZ-MOI.txt", "this text, in English / in French", "ce texte, en anglais / en français"),
                 ("MANIFEST.sha256", "SHA-256 of every other file (sha256sum format)", "SHA-256 de chaque autre fichier (format sha256sum)")]
    files.append(("README.txt", bundle_readme({**summary, "contents": [(n, e) for n, e, _ in contents]}, True).encode()))
    files.append(("LISEZ-MOI.txt", bundle_readme({**summary, "contents": [(n, f) for n, _, f in contents]}, False).encode()))
    files.sort()
    files.append(("MANIFEST.sha256", "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in files).encode()))
    top = f"verifbox-dossier-{c['identifiant'][:8]}/"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        for n, d in files:
            zi = zipfile.ZipInfo(top + n, now.timetuple()[:6]); zi.external_attr = 0o100644 << 16
            z.writestr(zi, d)


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
    p.add_argument("--bundle", metavar="FOLDER.zip", help="also write a proof folder (.zip) with every element needed to examine the proof "
                   "without VerifBox: proof, attestation, anchors, token, roots, keys, report, README, MANIFEST.sha256")
    p.add_argument("--bundle-include-file", action="store_true", help="put the original file in the proof folder (left out by default)")
    a = p.parse_args()
    bundle = {"trust": None, "root": None, "crl": None, "token": None}
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
        keys, origin, keys_hash, keys_raw = load_keys(a.keys)
    except Exception as e:
        print(f"ERROR: {e}"); return 2

    print(f"Public keys: {origin}\n  SHA-256 of the key file: {keys_hash}\n  Keys and revocation status as loaded now, {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
          + (" (local file: a revocation published after it was saved is not known here)" if a.keys else ""))
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
        # If the OpenTimestamps client is installed and the original file is at hand, check the anchor against
        # Bitcoin right away: "ots verify" is the only control that establishes the block, the structural check above does not.
        if shutil.which("ots") and a.file:
            bundle["file_block"] = ots_block_check(ots, "Bitcoin anchor of the file", check, file=a.file)
        elif shutil.which("ots") and same:
            # No original file: the anchor commits to the fingerprint itself, so the block can still be established from it.
            bundle["file_block"] = ots_block_check(ots, "Bitcoin anchor of the file fingerprint", check, digest=c["empreinte"])
        elif not a.ots:
            check(None, "Bitcoin anchor present: structural check only. Install the OpenTimestamps client (pip install opentimestamps-client) "
                        "and give the original file, or use --ots FILE.ots then 'ots verify', to establish the Bitcoin block.")
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
        if same and shutil.which("ots"):
            bundle["att_block"] = ots_block_check(att, "Bitcoin anchor of the attestation", check, digest=expected)
        elif same:
            check(None, "Attestation anchor: structural check only; install the OpenTimestamps client to establish its Bitcoin block.")
    else:
        check(None, "No anchor of the attestation (proof issued before the two-anchor format).")

    # IIC TSA time-stamp token (RFC 3161), over the file fingerprint.
    token = (proof.get("jetons") or {}).get("iic_tsa")
    if not token:
        check(None, "No IIC TSA time-stamp token in this proof (optional element, added since 10 October 2026): the signed time rests on the VerifBox signature alone.")
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
                bundle["trust"] = json.dumps(trust, ensure_ascii=False, indent=2).encode() + b"\n"
                if crl is None and trust.get("crl"):
                    with urllib.request.urlopen(urllib.parse.urljoin(IIC_TSA_TRUST_URL, trust["crl"]), timeout=15) as r:
                        crl = r.read()
            roots = [(d, hashlib.sha256(d).hexdigest() not in PINNED_IIC_TSA_ROOTS) for d in candidates
                     if hashlib.sha256(d).hexdigest() in pins]
            if not roots:
                check(None, "IIC TSA time-stamp token present, but no pinned IIC TSA root is available: not checked "
                            "(give --iic-root and --iic-root-sha256, or use a verifier version with the production root pinned).")
            else:
                bundle["root"] = next((d for d, extra in roots if not extra), roots[0][0])
                r = verify_iic_token(tsr, c["empreinte"], roots, IIC_TSA_POLICIES + [IIC_TSA_TEST_POLICY])
                if crl is not None:
                    r = verify_iic_token(tsr, c["empreinte"], roots, IIC_TSA_POLICIES + [IIC_TSA_TEST_POLICY], crl)
                bundle["crl"], bundle["token"] = crl, r
                label = "IIC TSA TEST token (test service, not a production proof)" if r["policy"] == IIC_TSA_TEST_POLICY else "IIC TSA time-stamp token (RFC 3161)"
                acc = f", accuracy +/- {r['accuracy']:g} s" if r["accuracy"] is not None else ""
                check(True if r["policy"] != IIC_TSA_TEST_POLICY else None,
                      f"{label}: {r['time'].strftime('%Y-%m-%d %H:%M:%S')} UTC{acc}, serial {r['serial']}, revocation: {r['revocation']}")
                gap = abs((r["time"] - parse_time(c["horodatage"])).total_seconds())
                check(gap <= 10, f"Token time and signed time agree to within 10 s (gap {gap:.0f} s)" if gap <= 10 else
                      f"The token time differs from the signed time by {gap:.0f} s (more than 10 s): the proof is inconsistent")
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
    if a.bundle:
        try:
            ots_keys = None
            if a.keys and os.path.exists(a.keys + ".ots"):
                ots_keys = open(a.keys + ".ots", "rb").read()
            elif not a.offline:
                with urllib.request.urlopen(KEYS_URL + ".ots", timeout=15) as r: ots_keys = r.read()
            write_bundle(a.bundle, proof, lines, verdict, keys_raw, ots_keys, bundle,
                         a.file if (a.file and a.bundle_include_file) else None, a.file)
            print(f"Proof folder written to {a.bundle} (check it with: unzip it, then sha256sum -c MANIFEST.sha256)")
        except Exception as e:
            print(f"ERROR: proof folder not written ({e})"); return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
