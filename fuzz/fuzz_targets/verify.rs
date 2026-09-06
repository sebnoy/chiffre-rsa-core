//! Fuzz `RsaPublicKey::verify` sur un couple (message, signature)
//! arbitraire, avec une clé publique FIXE — même raison que
//! `unwrap_key.rs` : générer une paire à chaque itération serait
//! prohibitif et n'apporterait rien à la propriété recherchée.
//!
//! Contrairement à `unwrap_key` (un seul `&[u8]` fuzzé), `verify` prend
//! deux entrées indépendantes : on les dérive d'un seul buffer fuzzé en
//! coupant à une position elle-même dérivée du buffer, pour que le
//! fuzzer explore les deux dimensions (longueur relative message/
//! signature, contenu de chacun) sans avoir besoin d'un type structuré.
//!
//! Propriété recherchée : jamais de panic, quels que soient message et
//! signature — toujours `Ok(())` ou `Err(RsaKeysError::SignatureInvalid)`.

#![no_main]

use chiffre_rsa_core::RsaPublicKey;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const FIXED_PUBLIC_KEY_SPKI_PEM: &str = include_str!("../../tests/vectors/fixed_test_key.pem");

fn fixed_public_key() -> &'static RsaPublicKey {
    static KEY: OnceLock<RsaPublicKey> = OnceLock::new();
    KEY.get_or_init(|| {
        // fixed_test_key.pem est une clé PRIVÉE PKCS#8 ; on en dérive la
        // clé publique via chiffre-rsa-core lui-même plutôt que de
        // maintenir un second fichier PEM public en plus.
        let key_pair = chiffre_rsa_core::RsaKeyPair::from_pkcs8_pem(FIXED_PUBLIC_KEY_SPKI_PEM, None)
            .expect("clé de fuzzing fixe invalide");
        key_pair.public_key()
    })
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // Le premier octet fixe la coupure entre message et signature, sur
    // le reste du buffer — façon simple d'obtenir deux entrées de
    // longueurs variables à partir d'un seul flux fuzzé.
    let cut = (data[0] as usize) % (data.len().max(1));
    let (message, signature) = data[1..].split_at(cut.min(data.len().saturating_sub(1)));

    let _ = fixed_public_key().verify(message, signature);
});
