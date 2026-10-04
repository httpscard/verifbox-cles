# VerifBox public signing keys

This repository publishes the public signing keys of **VerifBox** (https://verifbox.com), a file timestamping service operated by HTTPS CARD — Internet Identity Card Limited (company no. 09168431, London).

It exists so that anyone can check the VerifBox key file **without trusting verifbox.com alone**: the same fingerprint is published here, in the DNS of internetidentitycard.com (DNSSEC-signed), and on verifbox.com. A substituted key file would not match all three.

## Current key

| | |
|---|---|
| Key identifier | `258e57366bcdb6ce` |
| Status | active |
| In service since | 2026-10-03 06:20 UTC |
| Algorithms | Ed25519 (RFC 8032) + ML-DSA-65 (NIST FIPS 204) |
| SHA-256 of `verifbox-cles.json` | `e0f8ef8020965dca46c973a84d5d78ff52c9580c1c5979886bab2cb0f15c565d` |

## Check the key file

```bash
curl -s https://verifbox.com/.well-known/verifbox-cles.json | shasum -a 256
dig +short TXT _verifbox.internetidentitycard.com
```

Both must show the fingerprint above, which must also match `verifbox-cles.json` in this repository.

## Verify a VerifBox proof

### Without any technical skill: the offline page

1. Download `verifbox-verify-offline.html` from this repository (button "Download raw file").
2. Double-click it: it opens in your browser, on Windows, Mac or Linux.
3. Drop the proof (`.verifbox.json`) and the original file.

The page works without any internet connection and cannot make any network request. The public key file is included in it; its SHA-256 is shown at the bottom of the page, to compare with the fingerprint above.

### In Python

```bash
pip install cryptography dilithium-py
python3 verifbox_verify.py proof.verifbox.json original-file --ots anchor.ots
```

The verifier (`verifbox_verify.py`, MIT licence) checks the file fingerprint, both signatures, the key lifecycle and the DNS publication, without contacting the VerifBox service. Specification: https://verifbox.com/specification

## Key rotation

Keys are never deleted. On rotation, the old key signs the new one, the old key becomes `retiree`, and this repository, the DNS record and verifbox.com are updated together. The commit history of this repository is the public record of these changes.

---

# Clés publiques de signature de VerifBox

Ce dépôt publie les clés publiques de signature de **VerifBox** (https://verifbox.com), service d’horodatage de fichiers édité par HTTPS CARD — Internet Identity Card Limited (société n° 09168431, Londres).

Il permet de contrôler le fichier de clés de VerifBox **sans faire confiance au seul verifbox.com** : la même empreinte est publiée ici, dans le DNS d’internetidentitycard.com (signé par DNSSEC) et sur verifbox.com. Un fichier de clés substitué ne correspondrait pas aux trois.

Clé actuelle : `258e57366bcdb6ce`, active depuis le 3 octobre 2026 à 06:20 UTC. Empreinte SHA-256 du fichier `verifbox-cles.json` : `e0f8ef8020965dca46c973a84d5d78ff52c9580c1c5979886bab2cb0f15c565d`.

**Vérifier une preuve sans compétence technique** : téléchargez `verifbox-verify-offline.html` depuis ce dépôt, ouvrez-le d’un double-clic dans votre navigateur (Windows, Mac ou Linux), puis déposez la preuve (`.verifbox.json`) et le fichier d’origine. La page fonctionne sans connexion internet et ne peut envoyer aucune donnée sur le réseau. Son interface existe en français.

Autres méthodes : voir ci-dessus, ou https://verifbox.com/fr/specification
