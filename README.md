# chiffre-rsa-core

Primitives RSA (génération de clé, scellement/descellement de clé de
contenu, sérialisation, empreinte) pour l'écosystème `chiffre-*`. Ce crate
ne connaît ni format de fichier `.enc`, ni notion de "destinataire" ou de
trousseau de confiance — il expose uniquement les opérations
cryptographiques bas niveau consommées par `chiffre-rsa-enveloppe`
(orchestration multi-destinataires) et `chiffre-rsa-keystore` (gestion de
clés/trousseau), qui restent des crates séparées.

# Auteur et statut du projet

Ce crate atteint sa v1.1.0 (la v1.0.0 s'appuyait sur `chiffre-aes-core`
v2.0.0). Il s'appuie sur `chiffre-aes-core` v2.1.0
(tagué), qui apporte le support multi-destinataires (header v2,
`RawKey`, `Recipient`) utilisé ici — voir [NOTICE.md](./NOTICE.md) pour
l'état exact de cette dépendance.

Aucun audit de sécurité externe n'a été réalisé à ce jour. La conception
suit les mêmes principes de rigueur que `chiffre-aes-core` (choix
cryptographiques documentés et justifiés, tests contre des vecteurs
indépendants, fuzzing), mais ça ne remplace pas une revue par un tiers
qualifié avant tout usage en production.

## Documentation technique

Voir [FORMAT.md](./FORMAT.md) pour le détail des encodages produits (clé
publique SPKI, clé privée PKCS#8, empreinte, sortie OAEP), des 3 vecteurs
de test indépendants (générateur Python `cryptography`, voir
[scripts/generate_oaep_vectors.py](./scripts/generate_oaep_vectors.py)) et
des campagnes de fuzzing (voir [fuzz/](./fuzz/)).

# Architecture

`chiffre-rsa-core` a une seule dépendance non-cryptographique-générique :
`chiffre_aes_core`, dont il réutilise deux types déjà zeroizés/éprouvés
plutôt que d'en recréer des équivalents :

- `RawKey` — la clé de contenu (CEK) de 32 octets que `wrap_key`/
  `unwrap_key` scellent/descellent. `chiffre-rsa-core` ne construit ni
  n'inspecte jamais son contenu autrement qu'au travers de
  `RawKey::from_bytes`/`as_bytes`.
- `Password` (= `Zeroizing<String>`) — réutilisé tel quel pour protéger
  l'export PKCS#8 d'une clé privée, plutôt que de dupliquer un type
  équivalent.

Toutes les autres dépendances (`rsa`, `sha2`, `spki`, `pkcs8`, `zeroize`,
`rand_core`, `thiserror`) sont des briques génériques de l'écosystème
RustCrypto/pkcs — voir [NOTICE.md](./NOTICE.md).

```
chiffre-aes-core (RawKey, Password)
        ▲
        │ (type seulement, pas de logique)
        │
chiffre-rsa-core   ← ce crate
   RsaKeyPair, RsaPublicKey
   generate / wrap_key / unwrap_key
   to_pkcs8_pem / from_pkcs8_pem
   to_spki_pem / from_spki_pem
   fingerprint
        ▲
        │
chiffre-rsa-enveloppe (à venir)
   encrypt_file_for_recipients / decrypt_file_with_key
   orchestre N appels à wrap_key/unwrap_key + chiffre_aes_core
```

# Construction cryptographique

## RSA-4096-OAEP-SHA256

Taille de clé fixée en dur à 4096 bits — pas de paramètre, pas d'astuce
maison, un seul choix couvert par les tests et les vecteurs indépendants
(voir la discussion du choix RSA/attaque Marvin dans le cahier des
charges du projet). Le schéma de chiffrement est RSA-OAEP avec SHA-256
comme fonction de hash *et* comme fonction de hash pour MGF1 (label vide)
— c'est ce que produit `Oaep::new::<Sha256>()` de la crate `rsa`
(RustCrypto). Un `wrapped_key` RSA-4096-OAEP-SHA256 fait systématiquement
512 octets.

## PKCS#8 / SPKI

- Clé publique : encodée en SPKI (`SubjectPublicKeyInfo`), PEM
  (`-----BEGIN PUBLIC KEY-----`) ou DER selon l'usage.
- Clé privée : encodée en PKCS#8, PEM en clair (`-----BEGIN PRIVATE
  KEY-----`) ou chiffrée (`-----BEGIN ENCRYPTED PRIVATE KEY-----`) via
  PBES2 avec scrypt comme KDF — c'est le seul KDF non déprécié exposé par
  la crate `pkcs8`/`pkcs5` pour ce format ; Argon2id, utilisé côté
  `chiffre-aes-core` pour son propre mot de passe de container, n'est pas
  standardisé en PBES2 et n'est donc pas une option ici.
- Des variantes DER brutes existent aussi : `to_pkcs8_der`/
  `from_pkcs8_der` (clé privée, **non chiffré** — le chiffrement reste
  la responsabilité de l'application, via `chiffre_aes_core`
  directement) et `to_spki_der`/`from_spki_der` (clé publique). Utile
  quand un format transporte le DER encodé en base64 plutôt qu'un PEM
  complet — c'est le cas du format de document de clé de
  `chiffre-rsa-keystore`.

## Signature (RSA-PSS-SHA256)

`RsaKeyPair::sign`/`RsaPublicKey::verify` — RSA-PSS avec SHA-256 comme
hash et MGF1, sel de 32 octets (taille de sortie SHA-256, comportement
par défaut de `rsa::pss::BlindedSigningKey`). Signent/vérifient un `&[u8]`
arbitraire : ce crate ne sait rien d'un éventuel format de document —
c'est à l'appelant (`chiffre-rsa-keystore`) de construire un encodage
déterministe des champs à signer avant d'appeler `sign`.

`sign` utilise `BlindedSigningKey` plutôt que `SigningKey` : même
opération RSA-PSS, mais avec un masquage de l'exposant privé pendant le
calcul qui réduit la surface d'attaque par canal auxiliaire — cohérent
avec la prudence déjà appliquée au choix de la crate `rsa` (mainline)
pour OAEP.

## Empreinte de clé publique

SHA-256 de l'encodage DER SPKI de la clé publique **seule** — jamais
d'une enveloppe ou de métadonnées autour. Ce choix délibéré garde
l'empreinte stable indépendamment d'un futur format de métadonnées porté
par `chiffre-rsa-keystore` (identité, date de création, commentaire...) :
l'empreinte identifie la clé, pas un enregistrement qui la contient. Voir
[FORMAT.md](./FORMAT.md) §4.

# Modèle de sécurité

## Ce que RSA-OAEP garantit ici

- **Confidentialité du CEK scellé** : sans la clé privée correspondante,
  `wrapped_key` ne révèle rien sur le CEK au-delà de sa longueur (32
  octets, fixe, déjà connue par construction du format `.enc`).
- **Intégrité implicite du padding** : un `wrapped_key` altéré ou généré
  au hasard échoue au dépadding OAEP avec une probabilité écrasante —
  `unwrap_key` retourne une erreur plutôt qu'une clé de contenu
  incorrecte silencieuse.

## Ce que RSA-OAEP ne garantit PAS

- **Aucune authentification de l'expéditeur.** RSA-OAEP est un schéma de
  *chiffrement*, pas de *signature* : n'importe qui possédant la clé
  publique d'un destinataire peut lui sceller un CEK arbitraire. Rien
  dans `chiffre-rsa-core` ne garantit qui a produit un `wrapped_key`
  donné — c'est un problème hors du périmètre de ce crate (à traiter, le
  cas échéant, au niveau de `chiffre-rsa-enveloppe`/`keystore` si un
  besoin de non-répudiation apparaît).
- **Aucune protection contre une clé privée compromise.** Comme pour
  toute cryptographie asymétrique : la sécurité du système repose
  entièrement sur le secret de la clé privée. `to_pkcs8_pem`/
  `RsaKeyPair` zeroïsent la clé en mémoire à la destruction, mais ne
  peuvent rien contre une fuite du fichier PEM lui-même sur disque si mal
  protégé (voir la section mot de passe PKCS#8 ci-dessus).
- **Pas de protection contre le canal auxiliaire sur la génération de
  clé.** `RsaKeyPair::generate()` utilise `OsRng` (aléa du système
  d'exploitation) — la qualité de cet aléa dépend entièrement de
  l'environnement d'exécution, hors du contrôle de ce crate.

# Génération de clé bloquante

`RsaKeyPair::generate()` est **bloquant, plusieurs secondes** — la
génération d'une paire RSA-4096 (recherche de deux nombres premiers de
2048 bits) est intrinsèquement coûteuse, indépendamment de
l'implémentation. C'est un choix assumé plutôt qu'une limitation à
corriger : voir le cahier des charges du projet pour la discussion
complète. Ne jamais appeler cette fonction sur un thread UI/requête sans
l'entourer d'un mécanisme d'exécution asynchrone/en arrière-plan côté
appelant.

# Tests et vérifications

Trois niveaux, dans l'esprit de `chiffre-aes-core` :

1. **Tests unitaires** (`src/lib.rs`, module `tests`) — aller-retour
   `wrap_key`/`unwrap_key`, rejet d'une mauvaise clé privée, rejet d'un
   ciphertext corrompu, aller-retour PEM (SPKI et PKCS#8, avec et sans
   mot de passe), stabilité et distinction des empreintes.
2. **Vecteurs de test indépendants** (`tests/vectors.rs` +
   `tests/vectors/oaep_*.json`, `tests/pss_vectors.rs` +
   `tests/vectors/pss_*.json`) — générés par des scripts Python
   (`scripts/generate_oaep_vectors.py`, `scripts/generate_pss_vectors.py`)
   qui n'importent et ne dépendent d'aucun code de ce crate ni de la
   crate `rsa` : uniquement `cryptography` (pyca), une implémentation
   indépendante de RustCrypto. OAEP et PSS sont tous deux probabilistes
   (aucune API haut niveau pour fixer le sel/le seed) : les valeurs
   figées dans les vecteurs (`wrapped_key_hex`, `signature_hex`) ne sont
   pas reproductibles bit-à-bit à chaque exécution du script — voir la
   docstring de chaque script pour le détail de ce choix.
3. **Fuzzing** (`fuzz/`, `cargo-fuzz`) — quatre cibles :
   `unwrap_key` (ciphertext OAEP arbitraire contre une clé fixe),
   `verify` (couple message/signature arbitraire contre une clé fixe),
   `from_spki_pem` et `from_pkcs8_pem` (parsing PEM arbitraire, surface
   non authentifiée par construction). Voir [FORMAT.md](./FORMAT.md)
   pour le détail et les instructions d'exécution.

```bash
cargo test                              # unitaires + vecteurs indépendants
python3 scripts/generate_oaep_vectors.py  # régénérer les vecteurs (optionnel)
cargo fuzz run unwrap_key -- -max_total_time=60   # nécessite cargo-fuzz + nightly
```

# Compilation

Nécessite un toolchain Rust suffisamment récent pour l'édition 2024
(stabilisée en Rust 1.85) : `chiffre_aes_core` (dépendance git, en
attendant une release taguée incluant le header v2) tire `aes-gcm 0.11`
→ `aead 0.6` → `crypto-common 0.2`, qui la requiert.

```bash
rustc --version   # >= 1.85 recommandé
cargo build
cargo test
```

# Utiliser `chiffre-rsa-core`

```rust
use chiffre_rsa_core::{RsaKeyPair, RsaPublicKey};
use chiffre_aes_core::RawKey;

// Génération (bloquant, plusieurs secondes).
let alice = RsaKeyPair::generate()?;
let alice_public = alice.public_key();

// Export/rechargement de la clé publique.
let pem = alice_public.to_spki_pem();
let reloaded = RsaPublicKey::from_spki_pem(&pem)?;
assert_eq!(alice_public.fingerprint(), reloaded.fingerprint());

// Scellement d'un CEK pour Alice, puis descellement.
let cek = RawKey::generate_random();
let wrapped = alice_public.wrap_key(&cek)?;
let unwrapped = alice.unwrap_key(&wrapped)?;
assert_eq!(cek.as_bytes(), unwrapped.as_bytes());

// Export de la clé privée, protégée par mot de passe.
use zeroize::Zeroizing;
let password: chiffre_rsa_core::Password = Zeroizing::new("...".to_string());
let private_pem = alice.to_pkcs8_pem(Some(&password))?;
let reloaded_alice = RsaKeyPair::from_pkcs8_pem(&private_pem, Some(&password))?;
# Ok::<(), chiffre_rsa_core::RsaKeysError>(())
```

# Transparence et réutilisation

Comme `chiffre-aes-core`, ce crate documente ses choix (y compris ceux
qu'il ne fait pas, cf. modèle de sécurité ci-dessus) pour que quiconque
l'évalue ou le réutilise puisse le faire en connaissance de cause, sans
avoir à relire le code source pour en retrouver les hypothèses.

# Licence

MIT OR Apache-2.0, comme le reste de l'écosystème `chiffre-*`.
