#!/usr/bin/env python3
"""Build the "re-signed proof" vector: an attestation signed with a throw-away TEST key, whose signed time is
3 minutes before the (real) IIC TSA token of the demo file. Only the holder of a signing key can produce such a
proof; this script shows what the verifiers do with one, without touching the production key.

    pip install cryptography dilithium-py
    python3 make-test-key-vector.py            # writes test-key.json and test-key-shifted-time.json

Then:
    python3 ../verifbox_verify.py test-key-shifted-time.json demo-file.txt --keys test-key.json --root <ID>:<SHA256> \
        --offline --iic-root ../demo-iic-tsa/iic-tsa-root.pem
(the script prints the exact --root value; without it the verifier refuses the unknown key, which is the right default).
Expected: both signatures PASS, the real token PASS, and one FAIL: the token time differs from the signed time by 180 s.
"""
import base64, hashlib, json, pathlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from dilithium_py.ml_dsa import ML_DSA_65

HERE = pathlib.Path(__file__).parent
PREFIX = b"verifbox-preuve-v1\n"
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
canonical = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

demo = json.loads((HERE / "demo-file.verifbox.json").read_text())
ed = Ed25519PrivateKey.generate()
ed_pub = ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
pq_pub, pq_priv = ML_DSA_65.keygen()
key_id = hashlib.sha256(ed_pub + pq_pub).hexdigest()[:16]
full_hash = hashlib.sha256(ed_pub + pq_pub).hexdigest()

content = dict(demo["contenu"])
content["cle"] = key_id
content["horodatage"] = "2026-10-10T18:50:10.995Z"   # real token of this file: 18:53:11 UTC -> gap of 180 s
content["identifiant"] = hashlib.sha256(b"test-key-vector" + canonical(content)).hexdigest()[:32]
msg = PREFIX + canonical(content)
proof = {
    "contenu": content,
    "signatures": {"ed25519": b64u(ed.sign(msg)), "ml_dsa_65": b64u(ML_DSA_65.sign(pq_priv, msg))},
    "jetons": demo["jetons"],   # the genuine IIC TSA token over the same file fingerprint
    "informatif": {"note": "TEST VECTOR: attestation signed with a throw-away test key, signed time 3 minutes before the real token. Not a VerifBox proof."},
}
keys = {"format": "verifbox-cles-2", "cles": [{"cle": key_id, "statut": "active", "valide_depuis": "2026-10-01T00:00:00Z", "valide_jusqu": None,
                                               "ed25519_public": b64u(ed_pub), "mldsa65_public": b64u(pq_pub)}]}
(HERE / "test-key.json").write_text(json.dumps(keys, indent=1) + "\n")
(HERE / "test-key-shifted-time.json").write_text(json.dumps(proof, indent=1) + "\n")
print(f"test key {key_id}; run with:  --keys test-key.json --root {key_id}:{full_hash}")
