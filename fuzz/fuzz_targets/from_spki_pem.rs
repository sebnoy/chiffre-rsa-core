//! Fuzz `RsaPublicKey::from_spki_pem` sur une entrée texte arbitraire.
//!
//! Contrairement à `unwrap_key`, cette surface n'a besoin d'aucune clé
//! fixe : c'est justement le PARSING (délimiteurs PEM, base64, DER
//! SubjectPublicKeyInfo) qui est visé, avant toute opération
//! cryptographique. C'est une entrée typiquement non authentifiée avant
//! usage (une clé publique reçue d'un tiers, un fichier `.pub.pem` fourni
//! par l'utilisateur) — donc une bonne cible de fuzzing malgré l'absence
//! de secret impliqué.
//!
//! Propriété recherchée : jamais de panic, quelle que soit l'entrée —
//! `from_spki_pem` doit toujours retourner `Ok` ou
//! `Err(RsaKeysError::InvalidEncoding)`.

#![no_main]

use chiffre_rsa_core::RsaPublicKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `from_spki_pem` prend un `&str` : toute entrée non-UTF-8 est hors
    // du domaine de la fonction et ignorée ici (elle serait de toute
    // façon rejetée en amont, côté appelant, par la conversion
    // `bytes -> String`).
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = RsaPublicKey::from_spki_pem(text);
});
