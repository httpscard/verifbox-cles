# Public demonstration proof with the IIC TSA token

A real VerifBox proof, issued by the production service on 10 October 2026 — the day the IIC TSA time-stamp token went live — with the double Bitcoin anchoring and the RFC 3161 token. This time the original file is published too (`document-exemple.txt`, 40 bytes of plain text), so every check, including the OpenSSL one, can be replayed in full. This proof is the one behind the example certificate shown on verifbox.com.

| Item | Value |
|---|---|
| Proof identifier | `54b07a24cc8d404da5a127dfa2d818f6` |
| Declared time (signed by VerifBox) | 2026-10-10 18:53:10.995 UTC |
| Signing key | `258e57366bcdb6ce` |
| File fingerprint (SHA-256) | `0d94170ac58605a91251bb6b2b6bf5f9243995ecd23ed2c83af20b64ffa95529` |
| Attestation digest (specification, section 7) | `bd19eb760bb02c361faf3a6ecd8ca496c811beb83f7f6fde47caf16e08a7cddf` |
| IIC TSA token | 2026-10-10 18:53:11 UTC, accuracy ± 1 s, policy `1.3.6.1.4.1.67100.1.1.1.1`, serial `47d70c22c4f47cf4e0766104d85b056e` |
| Bitcoin block of both anchors | 970,811 (2026-10-10 19:00:07 UTC) |
| Transaction | `ea43d20ad4f936319bb48ca241975853a80705b3a47b0c5c7abc897b3deec525` |

IIC TSA is operated by the same company as VerifBox and is not an independent third party; it is not an eIDAS-qualified trust service.

## Files

- `document-exemple.txt`: the original file.
- `preuve-54b07a24.verifbox.json`: the completed proof, with both anchors and the token.
- `ancrage-fichier.ots`, `ancrage-attestation.ots`: the two OpenTimestamps anchors.
- `jeton-iic-tsa.tsr`: the RFC 3161 time-stamp token, extracted from the proof.
- `iic-tsa-root.pem`: the IIC TSA root certificate (`IIC TSA Root R1`, SHA-256 `86:52:E3:D1:3E:72:5F:7C:75:7C:FA:05:3D:64:13:60:AC:A4:43:CF:6C:09:D7:D6:DD:D4:4B:EA:85:1E:D3:B9`), a copy of the one published at https://verifbox.com/.well-known/iic-tsa.json.
- `verification.txt`: the output of the independent verifier on this proof and file.

## Replay the verification

**1. Signatures, key, file, anchors and token, with the independent Python verifier:**

```bash
pip install cryptography dilithium-py
python3 ../verifbox_verify.py preuve-54b07a24.verifbox.json document-exemple.txt
```

**2. Both anchors against the Bitcoin blockchain, with the official OpenTimestamps client:**

```bash
pip install opentimestamps-client
ots verify -d 0d94170ac58605a91251bb6b2b6bf5f9243995ecd23ed2c83af20b64ffa95529 ancrage-fichier.ots
ots verify -d bd19eb760bb02c361faf3a6ecd8ca496c811beb83f7f6fde47caf16e08a7cddf ancrage-attestation.ots
```

**3. The IIC TSA token, with OpenSSL alone:**

```bash
openssl ts -verify -data document-exemple.txt -in jeton-iic-tsa.tsr -CAfile iic-tsa-root.pem
openssl ts -reply -in jeton-iic-tsa.tsr -text
```

The first command must print `Verification: OK`; the second shows the policy, the serial number, the time and the accuracy. Any change to `document-exemple.txt`, even one byte, makes both the proof and the token fail.
