#!/usr/bin/env python3
"""
Générateur INDÉPENDANT (Python) de vecteurs de test pour la signature
RSA-PSS-SHA256 de chiffre-rsa-core (RsaKeyPair::sign / RsaPublicKey::verify).

Même principe que generate_oaep_vectors.py : uniquement `cryptography`
(pyca), aucune dépendance à ce crate ni à la crate `rsa`. Réutilise la
même clé RSA-4096 fixe que les vecteurs OAEP (voir fixed_test_key.pem)
pour ne pas multiplier les clés de test à maintenir.

RSA-PSS est, comme OAEP, un schéma PROBABILISTE (sel aléatoire à chaque
signature, RFC 8017 §8.1.1) : `signature_hex` est figé une fois pour
toutes après génération, pas reproductible bit-à-bit en relançant ce
script — même raisonnement que pour `wrapped_key_hex` côté OAEP, voir
la docstring de generate_oaep_vectors.py pour le détail.

Paramètres PSS : MGF1-SHA256, longueur de sel = 32 octets (taille de la
sortie SHA-256) — c'est le comportement par défaut de
`rsa::pss::BlindedSigningKey::<Sha256>::new(...)` côté Rust (RustCrypto),
donc le choix explicite ici pour que les vecteurs correspondent
exactement à ce que produit l'implémentation testée.
"""
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VECTORS_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "tests", "vectors"))
FIXED_KEY_PATH = os.path.join(VECTORS_DIR, "fixed_test_key.pem")

PSS_SALT_LEN = hashes.SHA256().digest_size  # 32


def pss_padding():
    return padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=PSS_SALT_LEN,
    )


def write_vector(name: str, vector: dict):
    os.makedirs(VECTORS_DIR, exist_ok=True)
    path = os.path.join(VECTORS_DIR, f"pss_{name}.json")
    with open(path, "w") as f:
        json.dump(vector, f, indent=2)
    print(f"pss_{name} ecrit : {path}")


def generate_positive_vector(name: str, message: bytes, description: str):
    with open(FIXED_KEY_PATH, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)
    public_key = private_key.public_key()

    signature = private_key.sign(message, pss_padding(), hashes.SHA256())

    # Auto-vérification avant d'écrire : le vecteur doit d'abord se
    # revérifier avec cette même implémentation indépendante.
    public_key.verify(signature, message, pss_padding(), hashes.SHA256())

    public_spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    vector = {
        "description": description,
        "algorithm": "RSA-PSS-SHA256 (MGF1-SHA256, sel de 32 octets)",
        "inputs": {
            "private_key_pkcs8_pem_file": "fixed_test_key.pem",
            "message_hex": message.hex(),
        },
        "expected": {
            "public_key_spki_der_hex": public_spki_der.hex(),
            "signature_hex": signature.hex(),
            "verify_must_succeed": True,
        },
    }
    write_vector(name, vector)
    return signature


def generate_negative_vector_tampered_message(name: str, original_message: bytes,
                                               tampered_message: bytes,
                                               source_signature: bytes,
                                               description: str):
    vector = {
        "description": description,
        "algorithm": "RSA-PSS-SHA256 (MGF1-SHA256, sel de 32 octets)",
        "inputs": {
            "private_key_pkcs8_pem_file": "fixed_test_key.pem",
            "message_hex": tampered_message.hex(),
            "signature_hex": source_signature.hex(),
        },
        "expected": {
            "verify_must_succeed": False,
        },
    }
    write_vector(name, vector)
    assert original_message != tampered_message


def main():
    # --- pss_001 : cas nominal ---------------------------------------------
    sig_001 = generate_positive_vector(
        name="001",
        message=b"Document de cle utilisateur independant - v1",
        description="Cas nominal : message court representatif d'un "
                     "encodage de champs de document.",
    )

    # --- pss_002 : message vide ---------------------------------------------
    generate_positive_vector(
        name="002",
        message=b"",
        description="Cas limite : message vide (aucun champ a signer, "
                     "verifie l'absence de cas particulier sur ce cas).",
    )

    # --- pss_003 : message long ---------------------------------------------
    generate_positive_vector(
        name="003",
        message=bytes(range(256)) * 20,  # 5120 octets
        description="Cas limite : message plus grand qu'un bloc de hash, "
                     "verifie l'absence de troncature.",
    )

    # --- pss_004 : negatif, message altere apres signature ------------------
    generate_negative_vector_tampered_message(
        name="004_tampered_message",
        original_message=b"Document de cle utilisateur independant - v1",
        tampered_message=b"Document de cle utilisateur INDEPENDANT - v1",
        source_signature=sig_001,
        description="Negatif : un seul caractere modifie par rapport au "
                     "message signe dans pss_001 - la verification doit "
                     "echouer proprement.",
    )


if __name__ == "__main__":
    main()
