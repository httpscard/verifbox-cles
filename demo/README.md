# Public demonstration proof

A real VerifBox proof, issued by the production service on 5 October 2026 with the double Bitcoin anchoring, published so that anyone can replay its verification. The original file (a photograph, `bitcoin-verifbox_proof.jpg`, 505,917 bytes) is not published: every check below works from the fingerprints alone.

| Item | Value |
|---|---|
| Proof identifier | `2661beaa84dd4721a852b7eded251d95` |
| Declared time (signed by VerifBox) | 2026-10-05 15:23:19.709 UTC |
| Signing key | `258e57366bcdb6ce` |
| File fingerprint (SHA-256) | `b1fce82bfcbb8816e9012fc2ad3598b3efaab40f346f9ac5a6522f3ac4164bcc` |
| Attestation digest (specification, section 7) | `5814b1345ea4f724dce920fae025ab1b5102241594de3a148173693a506fae18` |
| Bitcoin block of both anchors | 970,047 (2026-10-05 16:17:32 UTC) |
| Transaction | `ae145086ee971ba49f9da341ae5052b6c63f366049c2383d467193c8a5f8883c` |

## Files

- `preuve-2661beaa.verifbox.json`: the completed proof, with both anchors.
- `ancrage-fichier.ots`: the OpenTimestamps anchor of the file fingerprint.
- `ancrage-attestation.ots`: the OpenTimestamps anchor of the signed attestation.
- `verification.txt`: the output of the independent verifier on this proof.

## Replay the verification

**1. Signatures, key and anchors (no network needed except for the DNS cross-check):**

```bash
pip install cryptography dilithium-py
python3 ../verifbox_verify.py preuve-2661beaa.verifbox.json
```

Without the original file, the result is `VALID SIGNATURES (original file not checked …)`: the fingerprint inside the proof is signed, but nobody can confirm which file it belongs to without that file.

**2. Both anchors against the Bitcoin blockchain, with the official OpenTimestamps client:**

```bash
pip install opentimestamps-client
ots verify -d b1fce82bfcbb8816e9012fc2ad3598b3efaab40f346f9ac5a6522f3ac4164bcc ancrage-fichier.ots
ots verify -d 5814b1345ea4f724dce920fae025ab1b5102241594de3a148173693a506fae18 ancrage-attestation.ots
```

`ots verify` checks the anchors against the block headers of a Bitcoin node it can reach (a local Bitcoin Core node by default). Without a node, `ots info ancrage-fichier.ots` shows the full path of operations and the block it leads to, and the transaction can be seen on any explorer: [mempool.space](https://mempool.space/tx/ae145086ee971ba49f9da341ae5052b6c63f366049c2383d467193c8a5f8883c), [blockstream.info](https://blockstream.info/tx/ae145086ee971ba49f9da341ae5052b6c63f366049c2383d467193c8a5f8883c).

**3. Recompute the attestation digest yourself** from the proof, as defined in section 7 of the [specification](https://verifbox.com/specification): it must equal `5814b134…6fae18`. The verifier prints it.

---

# Preuve de démonstration publique

Une preuve VerifBox réelle, émise par le service en production le 5 octobre 2026 avec le double ancrage Bitcoin, publiée pour que chacun puisse en rejouer la vérification. Le fichier d’origine (une photographie, `bitcoin-verifbox_proof.jpg`, 505 917 octets) n’est pas publié : tous les contrôles ci-dessus fonctionnent à partir des seules empreintes.

Les commandes sont les mêmes qu’en anglais. Sans le fichier d’origine, le vérificateur conclut `VALID SIGNATURES (original file not checked …)` : l’empreinte contenue dans la preuve est bien signée, mais seul le fichier permet de confirmer à quel fichier elle correspond. `ots verify` contrôle les ancrages auprès d’un nœud Bitcoin (par défaut un nœud Bitcoin Core local) ; sans nœud, `ots info` montre le chemin complet jusqu’au bloc 970 047, et la transaction se consulte sur n’importe quel explorateur.
