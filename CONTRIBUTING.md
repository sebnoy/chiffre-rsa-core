# Contribuer

Merci de l'intérêt porté à ce projet !

## Avant de proposer une PR

- Pour tout changement touchant la cryptographie (`src/lib.rs` —
  génération, OAEP, PKCS#8/SPKI, empreinte) : ouvrez d'abord une
  discussion/issue pour valider l'approche avant d'investir du temps
  dans le code. C'est la partie la plus sensible de ce crate ; un choix
  qui semble anodin (paramètre OAEP, KDF PKCS#8, longueur de clé) peut
  avoir des conséquences de sécurité qui ne sont pas évidentes à la
  lecture du diff.
- `cargo test` doit passer, y compris les vecteurs de test indépendants
  (`tests/vectors.rs`) — voir [FORMAT.md](./FORMAT.md) §7. Si votre
  changement modifie un comportement couvert par un vecteur existant,
  régénérez-le avec `scripts/generate_oaep_vectors.py` plutôt que de
  modifier le JSON à la main.
- `cargo clippy -- -D warnings` doit passer.
- Si votre changement touche une des trois cibles de fuzzing
  (`fuzz/fuzz_targets/`), lancez `cargo fuzz run <cible>` quelques
  minutes localement avant la PR (nécessite `cargo-fuzz` + un toolchain
  nightly) — voir [FORMAT.md](./FORMAT.md) §8.
- Toute nouvelle dépendance doit être en licence permissive compatible
  (MIT, Apache-2.0, BSD, Zlib...) — pas de (L)GPL, pour ne pas
  contaminer la licence du crate. Mettez à jour
  [NOTICE.md](./NOTICE.md) en conséquence.

## Dépendance à `chiffre_aes_core`

Ce crate dépend actuellement de `chiffre_aes_core` via une révision git
précise, en attendant une release taguée incluant le header v2 (voir
[NOTICE.md](./NOTICE.md)). Si votre PR nécessite un commit plus récent de
`chiffre_aes_core`, mettez à jour le `rev` du `Cargo.toml` explicitement
dans la PR plutôt que de laisser un `cargo update` implicite le faire —
la revue doit pouvoir voir exactement quel changement de dépendance est
introduit.

## Licence des contributions

En soumettant une contribution, vous acceptez qu'elle soit publiée sous
la même double licence MIT OR Apache-2.0 que le reste du projet.

> Si vous envisagez un jour de proposer une licence commerciale séparée
> de `chiffre-rsa-core` à des tiers, il est recommandé de faire signer un
> CLA (Contributor License Agreement) simple à chaque contributeur
> externe, pour conserver le droit de re-licencier l'ensemble du code.
> Sans CLA, chaque contribution reste la propriété de son auteur sous
> MIT/Apache-2.0 uniquement.
