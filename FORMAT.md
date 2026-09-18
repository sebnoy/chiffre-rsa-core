# Spécification des encodages produits par `chiffre-rsa-core`

`chiffre-rsa-core` ne définit aucun format de fichier propre (le format
`.enc`, y compris son header v2 multi-destinataires, appartient à
`chiffre_aes_core` — voir son `FORMAT.md` §12). Ce document spécifie
uniquement les encodages que ce crate produit et consomme : clé publique,
clé privée, empreinte, et sortie du scellement OAEP — c'est-à-dire
exactement ce qu'un `Recipient.wrapped_key` (côté `chiffre_aes_core`
header v2) contient une fois qu'on sait qu'il a été produit par ce crate.

## 1. Vue d'ensemble

| Objet | Encodage | Fonction |
|---|---|---|
| Clé publique | SPKI (RFC 5280), PEM ou DER | `to_spki_pem` / `from_spki_pem` |
| Clé privée | PKCS#8 (RFC 5958), PEM, en clair ou chiffré | `to_pkcs8_pem` / `from_pkcs8_pem` |
| Empreinte de clé publique | 32 octets (SHA-256) | `fingerprint` |
| Clé de contenu scellée (`wrapped_key`) | 512 octets (RSA-4096-OAEP-SHA256) | `wrap_key` / `unwrap_key` |
| Clé privée (DER brut) | 4096 bits, PKCS#8 non chiffré | `to_pkcs8_der` / `from_pkcs8_der` |
| Clé publique (DER brut) | SPKI | `to_spki_der` / `from_spki_der` |
| Signature | 512 octets (RSA-PSS-SHA256, sel 32 octets) | `sign` / `verify` |

## 2. Clé publique — SPKI

`RsaPublicKey::to_spki_pem` produit un PEM `SubjectPublicKeyInfo`
standard :

```
-----BEGIN PUBLIC KEY-----
<base64 : DER SubjectPublicKeyInfo, algorithme rsaEncryption (OID
1.2.840.113549.1.1.1), module et exposant public encodés en PKCS#1>
-----END PUBLIC KEY-----
```

Aucune extension, aucun champ optionnel : c'est l'encodage SPKI le plus
simple possible pour une clé RSA, produit par `spki::EncodePublicKey`
(crate `spki`). `from_spki_pem` accepte exactement ce format ; tout
PEM/DER dont le label ou la structure ASN.1 ne correspond pas retourne
`RsaKeysError::InvalidEncoding` plutôt que de paniquer (voir §6 et
`fuzz/fuzz_targets/from_spki_pem.rs`).

## 3. Clé privée — PKCS#8

`RsaKeyPair::to_pkcs8_pem(password)` produit :

- **`password: None`** — PKCS#8 en clair :
  ```
  -----BEGIN PRIVATE KEY-----
  <base64 : DER PrivateKeyInfo, OneAsymmetricKey RSA au sens PKCS#1>
  -----END PRIVATE KEY-----
  ```
- **`password: Some(pw)`** — PKCS#8 chiffré (RFC 5958 EncryptedPrivateKeyInfo) :
  ```
  -----BEGIN ENCRYPTED PRIVATE KEY-----
  <base64 : DER EncryptedPrivateKeyInfo, PBES2 (RFC 8018), KDF = scrypt>
  -----END ENCRYPTED PRIVATE KEY-----
  ```

Le KDF est **scrypt**, pas Argon2id : Argon2id n'est pas un KDF
standardisé pour PBES2 dans l'écosystème `pkcs5`/`pkcs8` utilisé ici (à la
différence du mot de passe de container `chiffre_aes_core`, qui définit
son propre format de header et peut donc choisir librement Argon2id).
Paramètres scrypt : ceux par défaut de `pkcs5::pbes2` au moment de la
génération — pas de paramétrage exposé par `chiffre-rsa-core` en v1 (à
documenter précisément si un besoin de paramétrage apparaît).

`from_pkcs8_pem(pem, password)` :
- Avec `password: None`, tente un parsing PKCS#8 en clair. Retourne
  `RsaKeysError::InvalidEncoding` si le PEM est mal formé, **y compris**
  si le PEM fourni est en fait un `ENCRYPTED PRIVATE KEY` (label
  incompatible).
- Avec `password: Some(pw)`, tente un déchiffrement PBES2 avec `pw`.
  Retourne `RsaKeysError::WrongPassword` en cas d'échec — que la cause
  soit un mot de passe réellement incorrect ou un DER chiffré corrompu ;
  ces deux cas ne sont pas distingués (cohérent avec l'absence
  d'oracle de mot de passe : voir §6).

## 4. Empreinte de clé publique

```
fingerprint(pk) = SHA-256(DER(SubjectPublicKeyInfo(pk)))
```

Calculée sur l'encodage DER de la clé **seule** (§2), jamais sur une
enveloppe ou des métadonnées qui pourraient l'entourer dans un usage
amont (`chiffre-rsa-keystore` ou ailleurs). Conséquence directe : deux
appelants qui obtiennent la même `RsaPublicKey` par des chemins
différents (chargée depuis un PEM, ou dérivée d'une `RsaKeyPair` via
`public_key()`) obtiennent systématiquement la même empreinte — vérifié
par `all_positive_vectors_public_key_matches_fingerprint` dans
`tests/vectors.rs`, qui compare les deux chemins contre une empreinte
calculée indépendamment en Python.

32 octets, pas de troncature, pas d'encodage texte imposé par ce crate
(un appelant qui veut un identifiant court/lisible — type `SHA256:xxxx`
façon SSH — l'encode lui-même à partir de ces 32 octets bruts).

## 5. Scellement de clé de contenu (`wrap_key`/`unwrap_key`)

Schéma : **RSA-OAEP**, hash **SHA-256**, MGF1 avec **SHA-256**, label
vide. C'est exactement `rsa::Oaep::new::<Sha256>()` de la crate `rsa`
(RustCrypto) — aucun paramètre alternatif exposé par
`chiffre-rsa-core`.

- **Entrée de `wrap_key`** : une `RawKey` (`chiffre_aes_core`), 32 octets.
- **Sortie de `wrap_key`** / **entrée de `unwrap_key`** : `Vec<u8>` de
  **exactement 512 octets** pour une clé RSA-4096 — c'est la taille du
  module RSA (4096 bits = 512 octets), constante quel que soit le
  message pour OAEP. C'est la valeur vérifiée par
  `wrapped_key_length_matches_spec` (tests unitaires) et sur laquelle est
  dimensionnée `MAX_WRAPPED_KEY_LEN` (1024) côté `chiffre_aes_core` —
  volontairement plus large que 512 pour ne pas coupler la borne de
  policy d'un format générique (`chiffre_aes_core` accepte n'importe quel
  schéma de scellement en amont) à un choix spécifique à
  `chiffre-rsa-core`.
- **Sortie de `unwrap_key`** : une `RawKey` (32 octets), reconstruite par
  `RawKey::from_bytes` après dépadding OAEP réussi.

OAEP est **probabiliste** : deux appels à `wrap_key` avec le même `RawKey`
et la même clé publique produisent deux `wrapped_key` différents (l'aléa
de padding vient d'`OsRng`). C'est attendu, sans conséquence sur la
correction du descellement, et c'est pourquoi les vecteurs de test
indépendants (§8) figent un `wrapped_key` précis plutôt que d'exiger une
reproduction bit-à-bit.

## 6. Signature (`sign`/`verify`)

Schéma : **RSA-PSS**, hash **SHA-256**, MGF1 avec **SHA-256**, longueur
de sel = 32 octets (taille de sortie SHA-256 — comportement par défaut
de `rsa::pss::BlindedSigningKey`/`VerifyingKey` côté RustCrypto, choisi
explicitement plutôt que supposé implicite).

- **Entrée de `sign`** : un `&[u8]` arbitraire. Ce crate ne construit
  jamais lui-même cet encodage — c'est à l'appelant (`chiffre-rsa-
  keystore`) de produire un encodage déterministe des champs à signer
  avant d'appeler `sign`.
- **Sortie de `sign`** / **entrée de `verify`** : `Vec<u8>` de
  **exactement 512 octets** pour une clé RSA-4096 (même raison que pour
  `wrap_key` §5 : la taille d'une signature RSA-PSS est constante, égale
  à la taille du module).
- `sign` utilise `BlindedSigningKey` plutôt que `SigningKey` : masquage
  de l'exposant privé pendant le calcul, réduisant la surface d'attaque
  par canal auxiliaire (temps d'exécution) sur cette opération —
  cohérent avec la prudence déjà appliquée au choix de la crate `rsa`
  (mainline, §5 du cahier des charges) pour OAEP.

Comme OAEP, PSS est **probabiliste** (sel aléatoire à chaque signature) :
deux signatures du même message avec la même clé sont différentes octet
pour octet, sans que ça affecte la vérification. Les vecteurs de test
indépendants (§8) figent une `signature_hex` précise plutôt que d'exiger
une reproduction bit-à-bit — même raisonnement qu'OAEP.

`verify` ne distingue **jamais** "mauvaise clé", "message altéré" et
"signature corrompue" — les trois retournent
`RsaKeysError::SignatureInvalid` indistinctement, pour la même raison que
`unwrap_key` ne distingue pas ses propres cas d'échec (§7) : distinguer
romprait la propriété d'indistinguabilité recherchée face à une entrée
hostile.

## 7. Erreurs

`RsaKeysError` ne distingue les causes d'échec qu'au niveau utile à
l'appelant, jamais au niveau qui créerait un oracle exploitable :

| Variante | Quand |
|---|---|
| `GenerationFailed` | `RsaKeyPair::generate()` — échec de `OsRng` ou de la recherche de nombres premiers (en pratique quasi jamais observé). |
| `InvalidEncoding` | PEM/DER malformé, label incompatible, ou PKCS#8 chiffré présenté sans mot de passe. |
| `WrongPassword` | Échec de déchiffrement PBES2 — mot de passe incorrect **ou** DER chiffré corrompu, indistinctement (voir §3). |
| `WrapFailed` | Échec du chiffrement OAEP (en pratique quasi jamais observé, message ≤ taille de clé). |
| `UnwrapFailed` | Échec du dépadding OAEP — clé privée incorrecte **ou** ciphertext altéré/aléatoire, indistinctement : distinguer ces deux cas romprait la propriété d'indistinguabilité d'OAEP face à un padding oracle. |
| `SignatureInvalid` | Échec de `verify` — mauvaise clé, message altéré, ou signature corrompue, indistinctement (voir §6). |

Aucune de ces variantes ne doit jamais se manifester par un panic — c'est
précisément ce que vérifie le fuzzing (§9).

## 8. Vecteurs de test indépendants

Voir [scripts/generate_oaep_vectors.py](./scripts/generate_oaep_vectors.py)
(dépendance : `cryptography`, pyca — implémentation indépendante de
RustCrypto) et [tests/vectors/](./tests/vectors/).

| Vecteur | Ce qu'il couvre |
|---|---|
| `oaep_001` | Cas nominal, CEK à octets tous distincts. |
| `oaep_002` | CEK entièrement à zéro — absence de traitement spécial sur cette valeur. |
| `oaep_003` | CEK entièrement à `0xFF`. |
| `oaep_004_corrupted` | Négatif : premier octet du `wrapped_key` d'`oaep_001` inversé — le descellement doit échouer proprement. |
| `pss_001` | Cas nominal, message court représentatif d'un encodage de champs de document. |
| `pss_002` | Message vide. |
| `pss_003` | Message de 5120 octets — absence de troncature sur un message plus grand qu'un bloc de hash. |
| `pss_004_tampered_message` | Négatif : un caractère modifié dans le message signé par `pss_001` — la vérification doit échouer proprement. |

Chaque vecteur positif fixe : la clé privée (PKCS#8 PEM, la même clé de
test dans tous les vecteurs — voir `fixed_test_key.pem`), le CEK ou
message attendu, le DER SPKI (ou PEM, selon le vecteur) de la clé
publique, son empreinte SHA-256 calculée indépendamment en Python, et un
`wrapped_key`/`signature_hex` connu produit une fois par `cryptography`.
`tests/vectors.rs` et `tests/pss_vectors.rs` vérifient respectivement que
`unwrap_key`/`verify` reproduisent le résultat attendu pour chaque
vecteur, et que la clé publique — qu'elle soit dérivée de la clé privée
ou chargée depuis le PEM/DER SPKI du vecteur — produit l'empreinte
attendue.

## 9. Fuzzing

Voir [fuzz/](./fuzz/) (`cargo-fuzz`, nécessite un toolchain nightly).

| Cible | Entrée fuzzée | Ce qu'elle exerce |
|---|---|---|
| `unwrap_key` | `wrapped: &[u8]` arbitraire, contre une clé privée fixe (`tests/vectors/fixed_test_key.pem`) | Dépadding OAEP/PKCS#1 face à un ciphertext arbitraire. |
| `verify` | couple `(message, signature)` arbitraire, contre une clé publique fixe | Vérification PSS face à une entrée arbitraire — surface non authentifiée par construction (signature reçue d'un tiers). |
| `from_spki_pem` | texte UTF-8 arbitraire | Parsing PEM/DER SPKI face à une entrée non authentifiée par construction (clé publique reçue d'un tiers). |
| `from_pkcs8_pem` | texte UTF-8 arbitraire, chemin `password: None` uniquement | Parsing PEM/DER PKCS#8 en clair. Le chemin chiffré délègue à `pkcs5`/`pkcs8`, déjà fuzzées en amont — le refuzzer ici n'exercerait que le même code. |

`unwrap_key` et `verify` utilisent une clé **fixe** plutôt qu'une
génération par itération : générer une paire RSA-4096 à chaque exécution
du harnais (plusieurs secondes chacune, voir README §Génération de clé
bloquante) rendrait toute campagne de fuzzing sérieuse impraticable, sans
rien apporter à la propriété recherchée (robustesse du dépadding/de la
vérification face à une entrée arbitraire, indépendante de quelle paire
de clés est utilisée).

Aucune campagne prolongée n'a encore été menée à ce jour (crate récent) —
section à mettre à jour avec des résultats une fois une campagne
effectuée, dans le même esprit que `chiffre_aes_core/FORMAT.md` §11.

## 10. Statut

Document à jour à la date de rédaction (crate `chiffre-rsa-core` v1.0.0).
À réviser si l'un des choix ci-dessus change (paramètres scrypt exposés,
schéma OAEP paramétrable, etc.) — ce fichier fait foi sur les encodages
produits, indépendamment de l'implémentation.
