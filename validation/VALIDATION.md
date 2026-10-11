# VerifBox — reproducible validation report

**Version 1.3 — 11 October 2026.** Everything in this folder can be re-run by anyone, without an account and without trusting the result shown by verifbox.com. The expected outputs recorded in `expected/` were produced on 11 October 2026 with the verifiers published in this repository; the Bitcoin blocks named below are public and permanent.

Operator: HTTPS CARD — INTERNET IDENTITY CARD LIMITED (England and Wales no. 09168431). VerifBox and IIC TSA are operated by the same company; IIC TSA is designed to RFC 3161 / RFC 5816 and is not a qualified trust service. This report demonstrates that the published mechanisms work together; it is not an independent audit.

## 1. Test vectors

| File | SHA-256 | Proof | Issued (UTC) | IIC TSA token | Anchor ① (file) | Anchor ② (attestation) |
|---|---|---|---|---|---|---|
| `control-file.txt` (40 bytes) | `508e1f94…4afe26` | `control-file.verifbox.json`, id `5013a88d…e9d6b` | 2026-10-10 21:56:02.854 | 21:56:05, serial `361369691b…a01d` | block **970834**, tx `afbec7a2…acb0` | block **970834** |
| `demo-file.txt` (40 bytes) | `0d94170a…5529` | `demo-file.verifbox.json`, id `54b07a24…18f6` | 2026-10-10 18:53:10.995 | 18:53:11, serial `47d70c22…056e` | block **970811** | block **970811** |

Full digests: `expected/sha256sums.txt`. Both proofs are real production proofs; both carry the two completed Bitcoin anchors and an IIC TSA token under the production policy `1.3.6.1.4.1.67100.1.1.1.1`. Extracted artefacts of the control proof: `control-file.ots`, `control-attestation.ots`, `control-token.tsr`.

Negative vectors, all derived from the demo proof:

| File | What was changed | Expected |
|---|---|---|
| `altered-file.txt` | one newline appended to `demo-file.txt` | NOT VALID (fingerprint) |
| `demo-proof-without-anchors-and-token.json` | `ancrages` and `jetons` removed | VALID on signatures, with notes (weaker, not forged) |
| `demo-proof-corrupted-token.json` | last 40 characters of the token replaced | NOT VALID (token) |
| `demo-proof-shifted-time.json` | signed time moved back by 3 minutes | NOT VALID (both signatures, and token gap > 10 s) |
| `test-key-shifted-time.json` + `test-key.json` | re-signed with a throw-away test key, signed time 180 s before the real token | NOT VALID (gap > 10 s only; signatures PASS) — see 2.7 |

## 2. Independent checks and expected results

Install once: `pip install cryptography dilithium-py opentimestamps-client` (OpenSSL 3 for the token). Run every command from this folder.

### 2.1 Python verifier (signatures, keys, anchors, token)

```bash
python3 ../verifbox_verify.py control-file.verifbox.json control-file.txt
```
Expected: `expected/01-control-proof.txt` — every line `[PASS]`, including
`Bitcoin anchor of the file confirmed: block 970834, merkle root ded0fe15… matches blockstream.info and mempool.space`, `Bitcoin anchor of the attestation confirmed: block 970834, …` (both anchors are checked automatically when the `ots` client is installed; otherwise the verifier says so and section 2.3 does it by hand),
`IIC TSA time-stamp token (RFC 3161): 2026-10-10 21:56:05 UTC, accuracy +/- 1 s`, `Token time and signed time agree to within 10 s (gap 2 s)`, and `RESULT: VALID (signatures and file)`.

The verifier pins the VerifBox root key and the IIC TSA root certificate; it fetches the key file and checks it against the DNSSEC-signed record `_verifbox.internetidentitycard.com`.

### 2.2 RFC 3161 token with OpenSSL only (no VerifBox code)

```bash
openssl ts -verify -data control-file.txt -in control-token.tsr -CAfile ../demo-iic-tsa/iic-tsa-root.pem
openssl ts -reply -in control-token.tsr -text | grep -E "Status:|Policy OID|Time stamp:|Accuracy|TSA:"
```
Expected: `expected/02-openssl-token.txt` — `Verification: OK`, `Policy OID: 1.3.6.1.4.1.67100.1.1.1.1`, `Time stamp: Oct 10 21:56:05 2026 GMT`, `Accuracy: 0x01 seconds`, `TSA: … CN=IIC TSA tsa-2026-a`. The root's SHA-256 is `8652e3d13e725f7c757cfa053d641360aca443cf6c09d7d6ddd44bea851ed3b9`; compare it with https://www.internetidentitycard.com/tsa before trusting it.

### 2.3 Bitcoin anchors with the OpenTimestamps client only

```bash
ots --no-bitcoin verify -f control-file.txt control-file.ots
ots --no-bitcoin verify -d 24189485af8d71d5ca30424259a77c60047fb505e07414526c22b91c362b13e6 control-attestation.ots
```
Expected: `expected/03-ots-file.txt`, `expected/04-ots-attestation.txt` — both name **block 970834, merkle root `ded0fe153e2aee9fdba12a15ea3ae009fd9a0a74c90ff075925553c5891e2b00`** (the file anchor also lists later blocks from other calendars). With a Bitcoin node, `ots verify` (without `--no-bitcoin`) does the block check itself.

The digest `24189485…13e6` is SHA-256 of `verifbox-attestation-v1`, the canonical `contenu`, and the two signatures: it is what anchor ② commits to, so the signatures themselves are proven to pre-date block 970834.

### 2.4 The block, against any explorer

```bash
curl -s https://blockstream.info/api/block-height/970834
curl -s https://mempool.space/api/block/<hash>   # merkle_root
```
Expected: `expected/05-block-970834.txt` — merkle root `ded0fe15…2b00`, identical to the one the anchors commit to. Block 970834 was mined on 2026-10-10 at 22:05:35 UTC, nine minutes after the proof.

### 2.5 In a browser

- https://verifbox.com/verify — drop `control-file.verifbox.json`, then `control-file.txt`: valid proof; both anchors confirmed in block 970834; token 21:56:05 UTC.
- `../verifbox-verify-offline.html` — same files, with the network disconnected: valid proof; anchors reported as structurally checked only (the page cannot reach Bitcoin by design); token verified against the embedded root.

### 2.6 Negative cases

```bash
python3 ../verifbox_verify.py demo-file.verifbox.json demo-file.txt                          # expected/06: VALID
python3 ../verifbox_verify.py demo-file.verifbox.json altered-file.txt                       # expected/07: NOT VALID
python3 ../verifbox_verify.py demo-proof-without-anchors-and-token.json demo-file.txt       # expected/08: VALID, with notes
python3 ../verifbox_verify.py demo-proof-corrupted-token.json demo-file.txt                 # expected/09: NOT VALID
python3 ../verifbox_verify.py demo-proof-shifted-time.json demo-file.txt                    # expected/10: NOT VALID
```

What each one shows: a single changed byte breaks the fingerprint; removing the anchors and the token leaves a weaker but authentic proof (they sit outside the signed content, and the verifier says so); a damaged token is rejected; a signed time that disagrees with the token by more than ten seconds makes the proof invalid, in all three verifiers.

### 2.7 Re-signed proof with a test key: the gap rule on its own

`demo-proof-shifted-time.json` (2.6) fails on three counts at once, because moving the signed time also breaks the signatures. To show that the gap rule alone rejects a proof, `make-test-key-vector.py` generates a throw-away Ed25519 + ML-DSA-65 key, re-signs the demo attestation with its signed time set 180 s before the genuine IIC TSA token, and keeps that genuine token. The production key is not involved and no such tool exists for it.

```bash
python3 make-test-key-vector.py          # optional: regenerates test-key.json and test-key-shifted-time.json with a fresh key
python3 ../verifbox_verify.py test-key-shifted-time.json demo-file.txt \
    --keys test-key.json --root <KEYID>:<SHA256> --offline --iic-root ../demo-iic-tsa/iic-tsa-root.pem
```
`<KEYID>:<SHA256>` is printed by the generator (for the committed files: `519a044a17d3f175:519a044a17d3f175ca160b1d412a5d839baaa805eb4c5f981806ba77eb1b38ff`). Expected: `expected/11-test-key-shifted-time.txt` — both signatures `[PASS]`, the real token `[PASS]`, exactly one `[FAIL]`: `The token time differs from the signed time by 180 s (more than 10 s)`, and `RESULT: NOT VALID`. Without `--root` the verifier refuses the unknown key, which is the intended default; `--offline` is used because a local key file cannot match the DNS record of the production key (that mismatch would otherwise be reported as a second, unrelated FAIL).

### 2.8 Proof folder (`--bundle`)

The verifier can gather every element of a proof in one folder that a third party can examine without VerifBox (specification, section 12). The Verify page on verifbox.com produces the same folder, in the browser.

```bash
python3 ../verifbox_verify.py control-file.verifbox.json control-file.txt --bundle control-folder.zip
unzip control-folder.zip && cd verifbox-dossier-5013a88d && sha256sum -c MANIFEST.sha256 && cat summary.json
```
Expected: `expected/12-proof-folder.txt` — fourteen files `OK`, and a summary naming block **970834** for both anchors, the token serial `361369691b…a01d`, policy `1.3.6.1.4.1.67100.1.1.1.1` and root `8652e3d1…d3b9`. The folder adds no signature; its `README.txt` lists the commands of sections 2.1 to 2.4, run on the files it contains. `verification-report.txt` and `summary.json` are records of the run, not elements of proof.

Outputs `01` and `06` to `10` were re-recorded on 11 October 2026 with the current verifier, which also confirms the anchor of the attestation against the explorers and prints when the keys were loaded; the verdicts are unchanged.

## 3. What this report does not show

- It does not show the clock checks of IIC TSA (four time sources over TLS) from the outside: a token only carries the resulting time and its declared accuracy of ± 1 s. The nightly journal batches, time-stamped by DigiCert and anchored in Bitcoin, show after the fact that no token was back-dated; they do not make the second itself independent of the operator.
- It does not include a key revocation. The procedure is specified (specification, section 9) and rehearsed in test; a public rehearsal with a retired production key will be added to this report when the first rotation happens.
- `verifbox-cles.json.ots` (the anchor of the key file itself) was completed on 11 October 2026: block **970891**, merkle root `f7b5c1d9b65abd4517d6eb2a7a5204e2a1b074265d21c71e39ff2545291aaafe` (`ots --no-bitcoin verify -f ../verifbox-cles.json ../verifbox-cles.json.ots`). The key file therefore provably existed before 08:36 UTC that day.
- Bitcoin block times are not precise to the second (about two hours of tolerance); the anchors establish an upper bound, the token the second.

## 4. Re-running on your own file

Time-stamp any file on https://verifbox.com, keep the proof, come back for the completed proof once the anchors are confirmed, then run sections 2.1 to 2.4 on it. Nothing in the procedure depends on VerifBox being online except the completion of the anchors, which any OpenTimestamps calendar can also provide (`ots upgrade`).
