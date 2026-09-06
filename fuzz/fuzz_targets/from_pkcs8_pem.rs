//! Fuzz `RsaKeyPair::from_pkcs8_pem` (chemin sans mot de passe) sur une
//! entrée texte arbitraire.
//!
//! Ne couvre volontairement que le chemin `password: None` : le chemin
//! chiffré délègue le déchiffrement PBES2/scrypt à `pkcs5`/`pkcs8`
//! (RustCrypto), déjà fuzzé en amont dans ces crates elles-mêmes — le
//! réintroduire ici n'exercerait que le même code, pas une surface propre
//! à `chiffre-rsa-core`.
//!
//! Propriété recherchée : jamais de panic sur un PEM/DER PKCS#8 arbitraire
//! (tronqué, base64 invalide, DER mal formé, ou structurellement valide
//! mais avec des champs RSA incohérents) — toujours `Ok` ou
//! `Err(RsaKeysError::InvalidEncoding)`.

#![no_main]

use chiffre_rsa_core::RsaKeyPair;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = RsaKeyPair::from_pkcs8_pem(text, None);
});
