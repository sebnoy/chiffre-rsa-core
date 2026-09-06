# Notices tierces

⚠️ Ce fichier est un point de départ manuel. À régénérer automatiquement
à chaque changement de dépendances, par exemple avec :

```bash
cargo install cargo-about
cargo about generate about.hbs > NOTICE.md
```

ou plus simplement pour un premier inventaire :

```bash
cargo install cargo-license
cargo license
```

## Dépendances directes de `chiffre-rsa-core`

| Crate | Licence |
|---|---|
| rsa | MIT OR Apache-2.0 |
| sha2 | MIT OR Apache-2.0 |
| spki | Apache-2.0 OR MIT |
| pkcs8 | Apache-2.0 OR MIT |
| zeroize | Apache-2.0 OR MIT |
| rand_core | MIT OR Apache-2.0 |
| thiserror | MIT OR Apache-2.0 |
| chiffre_aes_core | MIT OR Apache-2.0 (ce projet — voir sa propre `NOTICE.md`) |

## Dépendances de développement uniquement (tests)

| Crate | Licence |
|---|---|
| serde | MIT OR Apache-2.0 |
| serde_json | MIT OR Apache-2.0 |

## Dépendance de statut particulier : `chiffre_aes_core`

`chiffre-rsa-core` dépend actuellement de `chiffre_aes_core` via une
révision git précise (`rev = "693b2a5"` sur `main`), **pas** une version
publiée sur crates.io — le support multi-destinataires (header v2,
`RawKey`, `Recipient`) n'existe pas encore dans le tag `v1.0.0`. Voir
[README.md](./README.md) et le `Cargo.toml`. Cette ligne de dépendance
devra être mise à jour vers une version taguée dès qu'elle sera
disponible ; la licence de `chiffre_aes_core` (MIT OR Apache-2.0) ne
change pas selon la façon dont elle est référencée.

## Dépendances transitives notables

`rsa` tire notamment `num-bigint-dig`, `num-traits`, `num-integer`,
`num-iter` (arithmétique grands nombres, MIT OR Apache-2.0),
`subtle`/`zeroize` (temps constant / effacement, MIT OR Apache-2.0), et
`signature` (traits `Signer`/`Verifier` utilisés par `sign`/`verify`,
Apache-2.0 OR MIT).
`pkcs8`/`spki` tirent `der`, `pem-rfc7468`, `base64ct`, `const-oid`
(toutes MIT OR Apache-2.0). Aucune dépendance transitive en (L)GPL
identifiée à ce jour — à reconfirmer avec `cargo about` / `cargo license`
avant chaque release, transitive comprise (`cargo tree` pour explorer
l'arbre complet).
