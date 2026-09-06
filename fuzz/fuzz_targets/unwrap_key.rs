//! Fuzz `RsaKeyPair::unwrap_key` sur un `wrapped` arbitraire, avec une clé
//! privée FIXE — générer une clé RSA-4096 à chaque itération de fuzzing
//! serait prohibitif (plusieurs secondes chacune), et n'apporterait rien
//! ici : la propriété recherchée porte sur la robustesse du parsing/du
//! dépadding OAEP face à un `wrapped` arbitraire, pas sur la génération de
//! clé elle-même (déjà couverte par les tests unitaires).
//!
//! Propriété recherchée : jamais de panic, quelle que soit la longueur ou
//! le contenu de `wrapped` (trop court, trop long, mal formé au sens
//! OAEP/PKCS#1, ou par pur hasard "presque" valide). `unwrap_key` doit
//! toujours retourner soit `Ok`, soit `Err(RsaKeysError::UnwrapFailed)` —
//! jamais paniquer, jamais boucler.

#![no_main]

use chiffre_rsa_core::RsaKeyPair;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// Clé de test fixe (aucune valeur réelle, générée uniquement pour ce
// harnais de fuzzing) — voir `scripts/generate_oaep_vectors.py` pour la
// même clé réutilisée côté vecteurs indépendants.
const FIXED_PRIVATE_KEY_PEM: &str = include_str!("../../tests/vectors/fixed_test_key.pem");

fn fixed_key() -> &'static RsaKeyPair {
    static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
    KEY.get_or_init(|| {
        RsaKeyPair::from_pkcs8_pem(FIXED_PRIVATE_KEY_PEM, None)
            .expect("clé de fuzzing fixe invalide")
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = fixed_key().unwrap_key(data);
});
