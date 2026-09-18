# Politique de sécurité

## Signaler une vulnérabilité

**Merci de ne pas ouvrir d'issue publique** pour toute faille touchant :
- la cryptographie (génération de clé RSA, OAEP, signature, empreinte),
- la gestion mémoire des secrets (clé privée, mot de passe de protection),
- une possibilité de contournement de la vérification de signature ou
  de correspondance de clé.

merci de prendre contact pour inclure :
- une description du problème et son impact potentiel,
- les étapes de reproduction ou un PoC minimal,
- la version/commit concerné.

## Délai de réponse visé

A définir

## Versions supportées

| Version | Supportée |
|---|---|
| dernière version publiée | ✅ |
| versions antérieures | ❌ |

## Périmètre

Ce dépôt couvre `chiffre-rsa-core`. Les vulnérabilités touchant
`chiffre_aes_core` (cœur symétrique) doivent être signalées sur
[son propre dépôt](https://github.com/sebnoy/chiffre-aes-core) ; celles
touchant l'orchestration multi-destinataires ou la gestion de
trousseau relèvent de `chiffre-rsa-enveloppe`/`chiffre-rsa-keystore`,
des crates séparées.
