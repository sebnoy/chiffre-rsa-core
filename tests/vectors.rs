//! Tests d'intégration à partir de vecteurs indépendants (générés en
//! Python avec `cryptography`, sans dépendance à la crate `rsa` ni à ce
//! crate — voir `scripts/generate_oaep_vectors.py` et
//! `tests/vectors/oaep_*.json`).
//!
//! Contrairement aux vecteurs symétriques de `chiffre-aes-core`, OAEP est
//! probabiliste : `wrapped_key_hex` n'est PAS reproductible bit-à-bit en
//! relançant le générateur — c'est un ciphertext connu, figé une fois pour
//! toutes, dont on vérifie qu'il se déchiffre vers le CEK attendu. Voir la
//! docstring de `generate_oaep_vectors.py` pour le détail de ce choix.
//!
//! Pour ajouter un vecteur : générer `oaep_NNN.json` (voir le script),
//! le déposer dans `tests/vectors/`, puis ajouter une entrée à
//! `POSITIVE_VECTOR_FILES` ou `NEGATIVE_VECTOR_FILES` ci-dessous.

use chiffre_rsa_core::{RsaKeyPair, RsaPublicKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct PositiveVector {
    #[allow(dead_code)]
    description: String,
    inputs: PositiveInputs,
    expected: PositiveExpected,
}

#[derive(Deserialize)]
struct PositiveInputs {
    private_key_pkcs8_pem: String,
    cek_hex: String,
}

#[derive(Deserialize)]
struct PositiveExpected {
    public_key_spki_pem: String,
    public_key_fingerprint_sha256_hex: String,
    wrapped_key_hex: String,
}

#[derive(Deserialize)]
struct NegativeVector {
    #[allow(dead_code)]
    description: String,
    inputs: NegativeInputs,
}

#[derive(Deserialize)]
struct NegativeInputs {
    private_key_pkcs8_pem: String,
    wrapped_key_hex: String,
}

/// Décodeur hexadécimal minimal, pour éviter d'ajouter une dépendance
/// `hex` juste pour les tests (même choix que `chiffre-aes-core`).
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex invalide dans le vecteur"))
        .collect()
}

/// Vecteurs positifs : `include_str!` exige un chemin littéral connu à la
/// compilation, cette liste explicite est donc le seul endroit à modifier
/// pour ajouter un vecteur.
const POSITIVE_VECTOR_FILES: &[(&str, &str)] = &[
    ("oaep_001", include_str!("vectors/oaep_001.json")),
    ("oaep_002", include_str!("vectors/oaep_002.json")),
    ("oaep_003", include_str!("vectors/oaep_003.json")),
];

const NEGATIVE_VECTOR_FILES: &[(&str, &str)] = &[(
    "oaep_004_corrupted",
    include_str!("vectors/oaep_004_corrupted.json"),
)];

#[test]
fn all_positive_vectors_unwrap_to_expected_cek() {
    for (name, json) in POSITIVE_VECTOR_FILES {
        let vector: PositiveVector =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("{name}: JSON invalide: {e}"));

        let key_pair = RsaKeyPair::from_pkcs8_pem(&vector.inputs.private_key_pkcs8_pem, None)
            .unwrap_or_else(|e| panic!("{name}: chargement clé privée: {e}"));

        let expected_cek = hex_decode(&vector.inputs.cek_hex);
        let wrapped = hex_decode(&vector.expected.wrapped_key_hex);

        let unwrapped = key_pair
            .unwrap_key(&wrapped)
            .unwrap_or_else(|e| panic!("{name}: unwrap_key a échoué: {e}"));

        assert_eq!(
            unwrapped.as_bytes().as_slice(),
            expected_cek.as_slice(),
            "{name}: le CEK descellé ne correspond pas au vecteur indépendant"
        );
    }
}

#[test]
fn all_positive_vectors_public_key_matches_fingerprint() {
    for (name, json) in POSITIVE_VECTOR_FILES {
        let vector: PositiveVector =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("{name}: JSON invalide: {e}"));

        // Deux chemins indépendants vers la même clé publique : (a) la
        // dérivation Rust depuis la clé privée du vecteur, (b) le PEM SPKI
        // exporté par `cryptography` dans le vecteur lui-même. Les deux
        // doivent produire la même empreinte, et cette empreinte doit
        // matcher celle calculée indépendamment par le script Python.
        let key_pair = RsaKeyPair::from_pkcs8_pem(&vector.inputs.private_key_pkcs8_pem, None)
            .unwrap_or_else(|e| panic!("{name}: chargement clé privée: {e}"));
        let derived_public = key_pair.public_key();

        let loaded_public = RsaPublicKey::from_spki_pem(&vector.expected.public_key_spki_pem)
            .unwrap_or_else(|e| panic!("{name}: chargement clé publique SPKI: {e}"));

        let expected_fingerprint = hex_decode(&vector.expected.public_key_fingerprint_sha256_hex);

        assert_eq!(
            derived_public.fingerprint().to_vec(),
            expected_fingerprint,
            "{name}: empreinte de la clé dérivée de la clé privée"
        );
        assert_eq!(
            loaded_public.fingerprint().to_vec(),
            expected_fingerprint,
            "{name}: empreinte de la clé chargée depuis le PEM SPKI du vecteur"
        );
    }
}

#[test]
fn all_negative_vectors_fail_to_unwrap() {
    for (name, json) in NEGATIVE_VECTOR_FILES {
        let vector: NegativeVector =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("{name}: JSON invalide: {e}"));

        let key_pair = RsaKeyPair::from_pkcs8_pem(&vector.inputs.private_key_pkcs8_pem, None)
            .unwrap_or_else(|e| panic!("{name}: chargement clé privée: {e}"));

        let wrapped = hex_decode(&vector.inputs.wrapped_key_hex);
        let result = key_pair.unwrap_key(&wrapped);

        assert!(
            result.is_err(),
            "{name}: le descellement d'un ciphertext corrompu aurait dû échouer"
        );
    }
}
