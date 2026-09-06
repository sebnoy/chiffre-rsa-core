//! Tests d'intégration à partir de vecteurs RSA-PSS indépendants (générés
//! en Python avec `cryptography` — voir `scripts/generate_pss_vectors.py`
//! et `tests/vectors/pss_*.json`). Même principe que `vectors.rs`
//! (vecteurs OAEP) : voir sa documentation en tête de fichier pour le
//! rappel du caractère probabiliste de PSS et ses conséquences sur la
//! reproductibilité des vecteurs.

use chiffre_rsa_core::RsaPublicKey;
use serde::Deserialize;

#[derive(Deserialize)]
struct PssVector {
    #[allow(dead_code)]
    description: String,
    inputs: PssInputs,
    expected: PssExpected,
}

#[derive(Deserialize)]
struct PssInputs {
    message_hex: String,
    /// Uniquement présent dans les vecteurs négatifs (le positif dérive
    /// sa propre signature via `expected.signature_hex`).
    signature_hex: Option<String>,
}

#[derive(Deserialize)]
struct PssExpected {
    public_key_spki_der_hex: Option<String>,
    signature_hex: Option<String>,
    verify_must_succeed: bool,
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex invalide dans le vecteur"))
        .collect()
}

const POSITIVE_VECTOR_FILES: &[(&str, &str)] = &[
    ("pss_001", include_str!("vectors/pss_001.json")),
    ("pss_002", include_str!("vectors/pss_002.json")),
    ("pss_003", include_str!("vectors/pss_003.json")),
];

const NEGATIVE_VECTOR_FILES: &[(&str, &str)] = &[(
    "pss_004_tampered_message",
    include_str!("vectors/pss_004_tampered_message.json"),
)];

#[test]
fn all_positive_pss_vectors_verify_successfully() {
    for (name, json) in POSITIVE_VECTOR_FILES {
        let vector: PssVector =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("{name}: JSON invalide: {e}"));

        assert!(vector.expected.verify_must_succeed, "{name}: vecteur mal étiqueté");

        let der = hex_decode(
            vector
                .expected
                .public_key_spki_der_hex
                .as_deref()
                .unwrap_or_else(|| panic!("{name}: public_key_spki_der_hex manquant")),
        );
        let public_key =
            RsaPublicKey::from_spki_der(&der).unwrap_or_else(|e| panic!("{name}: clé invalide: {e}"));

        let message = hex_decode(&vector.inputs.message_hex);
        let signature = hex_decode(
            vector
                .expected
                .signature_hex
                .as_deref()
                .unwrap_or_else(|| panic!("{name}: signature_hex manquant")),
        );

        public_key
            .verify(&message, &signature)
            .unwrap_or_else(|e| panic!("{name}: verify aurait dû réussir, a échoué: {e}"));
    }
}

#[test]
fn negative_pss_vector_fails_verification() {
    // La clé publique n'est volontairement pas répétée dans le vecteur
    // négatif (il réutilise celle de pss_001) : on la recharge à partir
    // du vecteur positif correspondant.
    let positive: PssVector = serde_json::from_str(POSITIVE_VECTOR_FILES[0].1).unwrap();
    let der = hex_decode(&positive.expected.public_key_spki_der_hex.unwrap());
    let public_key = RsaPublicKey::from_spki_der(&der).unwrap();

    for (name, json) in NEGATIVE_VECTOR_FILES {
        let vector: PssVector =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("{name}: JSON invalide: {e}"));

        assert!(!vector.expected.verify_must_succeed, "{name}: vecteur mal étiqueté");

        let message = hex_decode(&vector.inputs.message_hex);
        let signature = hex_decode(
            vector
                .inputs
                .signature_hex
                .as_deref()
                .unwrap_or_else(|| panic!("{name}: signature_hex manquant côté inputs")),
        );

        let result = public_key.verify(&message, &signature);
        assert!(
            result.is_err(),
            "{name}: la vérification aurait dû échouer (message altéré)"
        );
    }
}
