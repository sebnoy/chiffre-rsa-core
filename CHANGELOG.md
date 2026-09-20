# Changelog

## v1.1.0

Aligne la dépendance sur `chiffre_aes_core` **v2.1.0**. **Aucun changement de
code, de format ni d'API** de `chiffre-rsa-core`.

- **Dépendance : tag `v2.1.0`** de `chiffre_aes_core`. Ce crate réexporte
  `Password` (`pub type Password = chiffre_aes_core::Password`) et utilise
  `RawKey` : une application qui dépend à la fois de `chiffre_aes_core` et de
  `chiffre-rsa-core` doit n'avoir qu'**une seule** version de
  `chiffre_aes_core` dans son graphe, faute de quoi ces types, identiques de
  nom, sont incompatibles entre les deux versions.
- **Vérification** : les 28 tests du crate passent inchangés contre
  `chiffre_aes_core` v2.1.0 (API purement additive par rapport à v2.0.0).
- `Cargo.lock` mis à jour en conséquence.

## v1.0.0

Première version publiée de `chiffre-rsa-core` — primitives RSA bas
niveau pour l'écosystème `chiffre-*`, consommées par
`chiffre-rsa-enveloppe` (orchestration multi-destinataires) et
`chiffre-rsa-keystore` (gestion de clés/trousseau).

- **Génération de clé** — `RsaKeyPair::generate()`, RSA-4096 fixé en
  dur (pas de paramètre de taille).
- **Scellement/descellement de clé de contenu** — `wrap_key`/
  `unwrap_key`, RSA-OAEP-SHA256 (label vide, MGF1-SHA256). Un
  `wrapped_key` fait systématiquement 512 octets. Réutilise directement
  le type `RawKey` de `chiffre_aes_core` (v2.0.0) comme point de
  convergence pour la clé de contenu, plutôt que d'en recréer un
  équivalent.
- **Signature** — `sign`/`verify`, RSA-PSS-SHA256 (sel 32 octets, via
  `BlindedSigningKey` pour la protection contre les canaux auxiliaires).
  Signe un `&[u8]` arbitraire ; ne connaît aucun format de document
  (responsabilité de l'appelant).
- **Sérialisation** — clé publique en SPKI (PEM/DER), clé privée en
  PKCS#8 (PEM en clair ou chiffré via PBES2/scrypt, ou DER non chiffré).
  Réutilise le type `Password` (`Zeroizing<String>`) de
  `chiffre_aes_core` pour protéger l'export PKCS#8 chiffré.
- **Empreinte de clé publique** — SHA-256 de l'encodage DER SPKI de la
  clé publique seule (jamais d'une enveloppe ou de métadonnées autour).
- **Dépendance à `chiffre_aes_core` v2.0.0** (tag Git, pas encore
  publiée sur crates.io) — voir [NOTICE.md](./NOTICE.md) pour l'état
  exact de cette dépendance et de ses propres dépendances transitives.
- Vecteurs de test indépendants (générateur Python `cryptography`, voir
  [scripts/generate_oaep_vectors.py](./scripts/generate_oaep_vectors.py))
  et campagnes de fuzzing — voir [FORMAT.md](./FORMAT.md) et
  [fuzz/](./fuzz/).
- Aucun audit de sécurité externe réalisé à ce jour.
