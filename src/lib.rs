//! `chiffre-rsa-core` — primitives RSA (génération, OAEP, sérialisation,
//! empreinte) consommées par `chiffre-rsa-enveloppe` et
//! `chiffre-rsa-keystore`.
//!
//! Ce crate ne connaît rien d'un éventuel format de métadonnées ou de
//! confiance : il expose uniquement `RsaKeyPair`/`RsaPublicKey` et les
//! opérations bas niveau (scellement/descellement OAEP, PEM, empreinte).
//! Voir le cahier des charges, Partie 2 §3.

use chiffre_aes_core::RawKey;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rand_core::OsRng;
use rsa::{
    pss::{BlindedSigningKey, Signature as PssSignature, VerifyingKey as PssVerifyingKey},
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    traits::PublicKeyParts,
    Oaep, RsaPrivateKey, RsaPublicKey as InnerPublicKey,
};
use sha2::{Digest, Sha256};
use spki::{DecodePublicKey, EncodePublicKey};
use zeroize::Zeroizing;

/// Taille de clé RSA imposée en v1 — voir cahier des charges §4.
/// Volontairement non paramétrable : "pas d'astuce cryptographique
/// maison", un seul choix couvert par les tests et vecteurs indépendants.
const RSA_KEY_BITS: usize = 4096;

/// Mot de passe protégeant l'export PKCS#8 d'une clé privée. Réexport du
/// type déjà utilisé par `chiffre_aes_core` pour son propre mot de passe
/// de container — même garanties de zeroization, pas de duplication.
pub type Password = chiffre_aes_core::Password;

#[derive(Debug, thiserror::Error)]
pub enum RsaKeysError {
    #[error("échec de la génération de la paire de clés RSA")]
    GenerationFailed,
    #[error("PEM/DER invalide ou mal formé")]
    InvalidEncoding,
    #[error("mot de passe incorrect ou PKCS#8 chiffré corrompu")]
    WrongPassword,
    #[error("échec du scellement OAEP de la clé de contenu")]
    WrapFailed,
    #[error("échec du descellement OAEP (clé privée incorrecte ou donnée altérée)")]
    UnwrapFailed,
    #[error("signature RSA-PSS invalide (message altéré, mauvaise clé, ou signature corrompue)")]
    SignatureInvalid,
}

/// Paire de clés RSA-4096. La clé privée est zeroizée à la destruction
/// (portée par `RsaPrivateKey` de la crate `rsa`, qui implémente déjà
/// `ZeroizeOnDrop` en interne).
pub struct RsaKeyPair {
    inner: RsaPrivateKey,
}

/// Clé publique RSA-4096, encodage SPKI. Clonable : une clé publique n'a
/// pas besoin d'être zeroizée.
#[derive(Clone)]
pub struct RsaPublicKey {
    inner: InnerPublicKey,
}

impl RsaKeyPair {
    /// Génère une nouvelle paire de clés RSA-4096. **Bloquant, plusieurs
    /// secondes** — voir cahier des charges §10 ("génération de clé
    /// bloquante assumée").
    pub fn generate() -> Result<Self, RsaKeysError> {
        let inner = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BITS)
            .map_err(|_| RsaKeysError::GenerationFailed)?;
        Ok(Self { inner })
    }

    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            inner: self.inner.to_public_key(),
        }
    }

    /// Sérialise la clé privée en PKCS#8 PEM, chiffrée (PBES2/scrypt) si
    /// `password` est fourni, en clair sinon.
    pub fn to_pkcs8_pem(
        &self,
        password: Option<&Password>,
    ) -> Result<Zeroizing<String>, RsaKeysError> {
        match password {
            None => self
                .inner
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|_| RsaKeysError::InvalidEncoding),
            Some(pw) => self
                .inner
                .to_pkcs8_encrypted_pem(OsRng, pw.as_bytes(), LineEnding::LF)
                .map_err(|_| RsaKeysError::InvalidEncoding),
        }
    }

    /// Charge une clé privée depuis un PKCS#8 PEM, déchiffré avec
    /// `password` s'il est fourni (doit correspondre à ce qui a été
    /// utilisé à l'export).
    pub fn from_pkcs8_pem(pem: &str, password: Option<&Password>) -> Result<Self, RsaKeysError> {
        let inner = match password {
            None => {
                RsaPrivateKey::from_pkcs8_pem(pem).map_err(|_| RsaKeysError::InvalidEncoding)?
            }
            Some(pw) => RsaPrivateKey::from_pkcs8_encrypted_pem(pem, pw.as_bytes())
                .map_err(|_| RsaKeysError::WrongPassword)?,
        };
        Ok(Self { inner })
    }

    /// Descelle une clé de contenu (CEK) préalablement scellée pour cette
    /// paire de clés via [`RsaPublicKey::wrap_key`].
    pub fn unwrap_key(&self, wrapped: &[u8]) -> Result<RawKey, RsaKeysError> {
        let padding = Oaep::new::<Sha256>();
        let bytes = self
            .inner
            .decrypt(padding, wrapped)
            .map_err(|_| RsaKeysError::UnwrapFailed)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| RsaKeysError::UnwrapFailed)?;
        Ok(RawKey::from_bytes(bytes))
    }

    /// Signe `message` (arbitraire — cette fonction ne sait rien d'un
    /// éventuel format de document ; c'est à l'appelant, typiquement
    /// `chiffre-rsa-keystore`, de construire un encodage déterministe des
    /// champs à signer avant d'appeler cette fonction) avec RSA-PSS-
    /// SHA256, sel de même longueur que le hash (recommandation standard,
    /// comportement par défaut de `BlindedSigningKey`).
    ///
    /// Utilise `BlindedSigningKey` plutôt que `SigningKey` : même
    /// opération RSA-PSS, mais avec un masquage (blinding) de l'exposant
    /// privé pendant le calcul, qui réduit la surface d'attaque par
    /// canal auxiliaire (temps d'exécution) sur cette opération —
    /// cohérent avec la prudence déjà appliquée au choix de la crate
    /// `rsa` (mainline, cahier des charges §5).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signing_key = BlindedSigningKey::<Sha256>::new(self.inner.clone());
        let signature = signing_key.sign_with_rng(&mut OsRng, message);
        signature.to_bytes().to_vec()
    }

    /// Exporte la clé privée en DER PKCS#8 **non chiffré**. Le
    /// chiffrement (par mot de passe, via `chiffre_aes_core`) reste
    /// entièrement la responsabilité de l'application appelante —
    /// `chiffre-rsa-core` ne dépend toujours que de `RawKey`/`Password`
    /// issus de `chiffre_aes_core`, jamais de son API de chiffrement de
    /// fichier. Le résultat est zeroizé à la destruction
    /// (`Zeroizing<Vec<u8>>`), comme [`Self::to_pkcs8_pem`].
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, RsaKeysError> {
        let doc = self
            .inner
            .to_pkcs8_der()
            .map_err(|_| RsaKeysError::InvalidEncoding)?;
        Ok(Zeroizing::new(doc.as_bytes().to_vec()))
    }

    /// Charge une clé privée depuis un DER PKCS#8 **non chiffré** —
    /// pendant de [`Self::to_pkcs8_der`]. Si la clé provient d'un DER
    /// chiffré par l'application (via `chiffre_aes_core`), c'est à
    /// l'application de le déchiffrer d'abord ; cette fonction n'accepte
    /// que du PKCS#8 en clair, comme son nom l'indique.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, RsaKeysError> {
        let inner =
            RsaPrivateKey::from_pkcs8_der(der).map_err(|_| RsaKeysError::InvalidEncoding)?;
        Ok(Self { inner })
    }
}

impl RsaPublicKey {
    pub fn to_spki_pem(&self) -> String {
        self.inner
            .to_public_key_pem(LineEnding::LF)
            .expect("l'encodage SPKI d'une RsaPublicKey valide ne peut pas échouer")
    }

    pub fn from_spki_pem(pem: &str) -> Result<Self, RsaKeysError> {
        let inner =
            InnerPublicKey::from_public_key_pem(pem).map_err(|_| RsaKeysError::InvalidEncoding)?;
        Ok(Self { inner })
    }

    /// DER SPKI brut (pas de PEM, pas d'en-têtes) — utile quand un format
    /// de document transporte directement le DER encodé en base64
    /// (c'est le cas du format de document de clé de
    /// `chiffre-rsa-keystore`), plutôt qu'un PEM complet.
    pub fn to_spki_der(&self) -> Vec<u8> {
        self.inner
            .to_public_key_der()
            .expect("l'encodage DER d'une RsaPublicKey valide ne peut pas échouer")
            .as_bytes()
            .to_vec()
    }

    /// Pendant de [`Self::to_spki_der`].
    pub fn from_spki_der(der: &[u8]) -> Result<Self, RsaKeysError> {
        let inner =
            InnerPublicKey::from_public_key_der(der).map_err(|_| RsaKeysError::InvalidEncoding)?;
        Ok(Self { inner })
    }

    /// SHA-256 de l'encodage DER SubjectPublicKeyInfo de la clé seule —
    /// voir cahier des charges §7 : jamais d'une enveloppe/métadonnée
    /// autour, pour que l'empreinte reste stable indépendamment d'un
    /// futur format de métadonnées porté par `chiffre-rsa-keystore`.
    pub fn fingerprint(&self) -> [u8; 32] {
        let der = self
            .inner
            .to_public_key_der()
            .expect("l'encodage DER d'une RsaPublicKey valide ne peut pas échouer");
        let mut hasher = Sha256::new();
        hasher.update(der.as_bytes());
        hasher.finalize().into()
    }

    /// Scelle une clé de contenu (CEK) pour cette clé publique (RSA-OAEP,
    /// SHA-256 comme hash et MGF1) — voir cahier des charges §4.
    pub fn wrap_key(&self, key: &RawKey) -> Result<Vec<u8>, RsaKeysError> {
        let padding = Oaep::new::<Sha256>();
        self.inner
            .encrypt(&mut OsRng, padding, key.as_bytes())
            .map_err(|_| RsaKeysError::WrapFailed)
    }

    /// Taille en bits du module RSA (4096 pour toute clé générée par
    /// [`RsaKeyPair::generate`] — mais une clé *chargée* via
    /// [`Self::from_spki_pem`] peut en principe provenir d'un autre outil
    /// et avoir une taille différente : ce n'est délibérément **pas**
    /// rejeté ici, cette décision de politique (accepter ou non une
    /// taille non conforme à cet écosystème) appartient à l'appelant —
    /// voir `chiffre-rsa-keystore::classify_public_key`, qui expose cette
    /// valeur précisément pour que l'application puisse la fonder).
    pub fn key_size_bits(&self) -> u32 {
        (self.inner.size() as u32) * 8
    }

    /// Vérifie `signature` (RSA-PSS-SHA256, produite par
    /// [`RsaKeyPair::sign`]) sur `message`. Ne distingue pas "mauvaise
    /// clé", "message altéré" et "signature corrompue" — comme pour
    /// [`RsaKeyPair::unwrap_key`], distinguer ces cas romprait la
    /// propriété d'indistinguabilité recherchée face à une entrée
    /// hostile.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), RsaKeysError> {
        let sig =
            PssSignature::try_from(signature).map_err(|_| RsaKeysError::SignatureInvalid)?;
        let verifying_key = PssVerifyingKey::<Sha256>::new(self.inner.clone());
        verifying_key
            .verify(message, &sig)
            .map_err(|_| RsaKeysError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    // La génération RSA-4096 coûte plusieurs secondes (voir §10 du
    // cahier des charges) : une seule paire est générée et partagée entre
    // la plupart des tests plutôt que d'en regénérer une par test.
    // `test_key_b` sert uniquement aux tests qui ont explicitement besoin
    // de deux clés distinctes.
    fn test_key_a() -> &'static RsaKeyPair {
        static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
        KEY.get_or_init(|| RsaKeyPair::generate().expect("génération de clé A"))
    }

    fn test_key_b() -> &'static RsaKeyPair {
        static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
        KEY.get_or_init(|| RsaKeyPair::generate().expect("génération de clé B"))
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let key_pair = test_key_a();
        let public = key_pair.public_key();
        let cek = RawKey::generate_random();

        let wrapped = public.wrap_key(&cek).expect("wrap_key");
        let unwrapped = key_pair.unwrap_key(&wrapped).expect("unwrap_key");

        assert_eq!(cek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn wrapped_key_length_matches_spec() {
        // FORMAT.md §12.3 : RSA-4096-OAEP-SHA256 produit 512 octets —
        // c'est la valeur sur laquelle est dimensionnée
        // MAX_WRAPPED_KEY_LEN (1024) côté chiffre_aes_core.
        let public = test_key_a().public_key();
        let cek = RawKey::generate_random();
        let wrapped = public.wrap_key(&cek).expect("wrap_key");
        assert_eq!(wrapped.len(), 512);
    }

    #[test]
    fn unwrap_with_wrong_private_key_fails() {
        let cek = RawKey::generate_random();
        let wrapped = test_key_a()
            .public_key()
            .wrap_key(&cek)
            .expect("wrap_key avec la clé A");

        // Descellement avec la clé B (mauvaise clé privée) : doit échouer,
        // pas produire silencieusement une clé de contenu incorrecte.
        let result = test_key_b().unwrap_key(&wrapped);
        assert!(matches!(result, Err(RsaKeysError::UnwrapFailed)));
    }

    #[test]
    fn unwrap_rejects_corrupted_ciphertext() {
        let cek = RawKey::generate_random();
        let mut wrapped = test_key_a()
            .public_key()
            .wrap_key(&cek)
            .expect("wrap_key");
        // Altère un octet du ciphertext scellé.
        wrapped[0] ^= 0xFF;

        let result = test_key_a().unwrap_key(&wrapped);
        assert!(matches!(result, Err(RsaKeysError::UnwrapFailed)));
    }

    #[test]
    fn spki_pem_roundtrip_preserves_fingerprint() {
        let public = test_key_a().public_key();
        let pem = public.to_spki_pem();

        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));

        let reloaded = RsaPublicKey::from_spki_pem(&pem).expect("from_spki_pem");
        assert_eq!(public.fingerprint(), reloaded.fingerprint());
    }

    #[test]
    fn from_spki_pem_rejects_garbage() {
        let result = RsaPublicKey::from_spki_pem("pas un PEM valide");
        assert!(matches!(result, Err(RsaKeysError::InvalidEncoding)));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let public = test_key_a().public_key();
        assert_eq!(public.fingerprint(), public.fingerprint());
    }

    #[test]
    fn fingerprint_differs_between_distinct_keys() {
        let fp_a = test_key_a().public_key().fingerprint();
        let fp_b = test_key_b().public_key().fingerprint();
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key_pair = test_key_a();
        let public = key_pair.public_key();
        let message = b"contenu arbitraire a signer";

        let signature = key_pair.sign(message);
        public.verify(message, &signature).expect("verify");
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let key_pair = test_key_a();
        let public = key_pair.public_key();
        let signature = key_pair.sign(b"message original");

        let result = public.verify(b"message modifie", &signature);
        assert!(matches!(result, Err(RsaKeysError::SignatureInvalid)));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let key_pair = test_key_a();
        let public = key_pair.public_key();
        let mut signature = key_pair.sign(b"message");
        signature[0] ^= 0xFF;

        let result = public.verify(b"message", &signature);
        assert!(matches!(result, Err(RsaKeysError::SignatureInvalid)));
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let signature = test_key_a().sign(b"message");
        let wrong_public = test_key_b().public_key();

        let result = wrong_public.verify(b"message", &signature);
        assert!(matches!(result, Err(RsaKeysError::SignatureInvalid)));
    }

    #[test]
    fn verify_rejects_garbage_signature_bytes() {
        let public = test_key_a().public_key();
        // Ni une taille de signature RSA-4096 valide (512 octets),
        // ni un contenu qui aurait un sens — doit échouer proprement,
        // jamais paniquer.
        let result = public.verify(b"message", b"pas une signature");
        assert!(matches!(result, Err(RsaKeysError::SignatureInvalid)));
    }

    #[test]
    fn pkcs8_der_roundtrip() {
        let key_pair = test_key_a();
        let original_fingerprint = key_pair.public_key().fingerprint();

        let der = key_pair.to_pkcs8_der().expect("to_pkcs8_der");
        let reloaded = RsaKeyPair::from_pkcs8_der(&der).expect("from_pkcs8_der");

        assert_eq!(original_fingerprint, reloaded.public_key().fingerprint());
    }

    #[test]
    fn from_pkcs8_der_rejects_garbage() {
        let result = RsaKeyPair::from_pkcs8_der(b"pas un DER valide");
        assert!(matches!(result, Err(RsaKeysError::InvalidEncoding)));
    }

    #[test]
    fn spki_der_roundtrip_preserves_fingerprint() {
        let public = test_key_a().public_key();
        let der = public.to_spki_der();

        let reloaded = RsaPublicKey::from_spki_der(&der).expect("from_spki_der");
        assert_eq!(public.fingerprint(), reloaded.fingerprint());
    }

    #[test]
    fn from_spki_der_rejects_garbage() {
        let result = RsaPublicKey::from_spki_der(b"pas un DER valide");
        assert!(matches!(result, Err(RsaKeysError::InvalidEncoding)));
    }

    #[test]
    fn spki_der_and_spki_pem_describe_the_same_key() {
        // Le DER brut (to_spki_der) doit être le même contenu que celui
        // encapsulé dans le PEM (to_spki_pem) — juste sans les en-têtes
        // ni le base64. On le vérifie indirectement via l'empreinte
        // (SHA-256 du DER), déjà exercée par les autres tests, et ici en
        // vérifiant que les deux chemins de chargement (PEM et DER)
        // convergent vers la même clé.
        let public = test_key_a().public_key();
        let via_der = RsaPublicKey::from_spki_der(&public.to_spki_der()).unwrap();
        let via_pem = RsaPublicKey::from_spki_pem(&public.to_spki_pem()).unwrap();
        assert_eq!(via_der.fingerprint(), via_pem.fingerprint());
    }

    #[test]
    fn key_size_bits_reports_4096_for_generated_key() {
        let public = test_key_a().public_key();
        assert_eq!(public.key_size_bits(), 4096);
    }

    #[test]
    fn pkcs8_pem_roundtrip_without_password() {
        let key_pair = test_key_a();
        let original_fingerprint = key_pair.public_key().fingerprint();

        let pem = key_pair.to_pkcs8_pem(None).expect("to_pkcs8_pem");
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));

        let reloaded = RsaKeyPair::from_pkcs8_pem(&pem, None).expect("from_pkcs8_pem");
        assert_eq!(original_fingerprint, reloaded.public_key().fingerprint());
    }

    #[test]
    fn pkcs8_pem_roundtrip_with_correct_password() {
        let key_pair = test_key_a();
        let original_fingerprint = key_pair.public_key().fingerprint();
        let password: Password = Zeroizing::new("mot-de-passe-de-test-très-robuste".to_string());

        let pem = key_pair
            .to_pkcs8_pem(Some(&password))
            .expect("to_pkcs8_pem chiffré");
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));

        let reloaded =
            RsaKeyPair::from_pkcs8_pem(&pem, Some(&password)).expect("from_pkcs8_pem chiffré");
        assert_eq!(original_fingerprint, reloaded.public_key().fingerprint());
    }

    #[test]
    fn pkcs8_pem_rejects_wrong_password() {
        let key_pair = test_key_a();
        let password: Password = Zeroizing::new("bon-mot-de-passe".to_string());
        let wrong_password: Password = Zeroizing::new("mauvais-mot-de-passe".to_string());

        let pem = key_pair
            .to_pkcs8_pem(Some(&password))
            .expect("to_pkcs8_pem chiffré");

        let result = RsaKeyPair::from_pkcs8_pem(&pem, Some(&wrong_password));
        assert!(matches!(result, Err(RsaKeysError::WrongPassword)));
    }

    #[test]
    fn pkcs8_pem_encrypted_rejected_without_password() {
        let key_pair = test_key_a();
        let password: Password = Zeroizing::new("un-mot-de-passe".to_string());
        let pem = key_pair
            .to_pkcs8_pem(Some(&password))
            .expect("to_pkcs8_pem chiffré");

        // Tenter de charger un PKCS#8 chiffré sans fournir de mot de passe
        // doit échouer proprement, pas paniquer.
        let result = RsaKeyPair::from_pkcs8_pem(&pem, None);
        assert!(result.is_err());
    }
}
