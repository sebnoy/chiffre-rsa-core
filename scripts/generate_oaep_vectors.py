#!/usr/bin/env python3
"""
Générateur INDÉPENDANT (Python) de vecteurs de test pour chiffre-rsa-core,
à partir de la seule spécification (RSA-4096-OAEP-SHA256, MGF1-SHA256,
label vide, empreinte = SHA-256 de l'encodage DER SubjectPublicKeyInfo).

N'importe et ne dépend d'AUCUN code du crate Rust ni de la crate `rsa`
(RustCrypto) : uniquement `cryptography` (pyca), une implémentation
indépendante largement auditée. Même principe que
chiffre-aes-core/core/scripts/generate_vector.py.

Particularité par rapport aux vecteurs symétriques de chiffre-aes-core :
OAEP est un schéma de chiffrement PROBABILISTE (un octet aléatoire de
"seed" est mélangé à chaque chiffrement, cf. RFC 8017 §7.1.1). Il n'existe
pas d'API haut niveau dans `cryptography` pour fixer ce seed. Par
conséquent, contrairement aux vecteurs v1/v2 de chiffre-aes-core (qui sont
bit-à-bit reproductibles à partir de constantes déclarées), les champs
`wrapped_key_hex` ci-dessous sont figés au moment de la génération : relancer
ce script produit un `wrapped_key_hex` DIFFÉRENT à chaque fois (mais qui
continue de se déchiffrer correctement vers le même `cek_hex`). C'est
attendu et sans conséquence : la propriété testée côté Rust n'est jamais
"ce ciphertext exact", mais "ce ciphertext connu, produit une fois par une
implémentation indépendante, se déchiffre vers le CEK attendu" — exactement
ce que couvre un vecteur de test pour un schéma probabiliste (voir par
exemple les vecteurs OAEP du NIST CAVP, qui figent eux aussi un ciphertext
par vecteur plutôt que d'exiger une reproduction bit-à-bit).

La clé RSA-4096 elle-même est en revanche parfaitement fixe (générée une
fois, codée en dur ci-dessous) : c'est elle qui rend les vecteurs
reproductibles et indépendants du hasard à chaque exécution, une fois
`wrapped_key_hex` figé dans le JSON committé.
"""
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VECTORS_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "tests", "vectors"))

# Clé RSA-4096 FIXE, générée une seule fois pour ce projet et codée en dur
# ici (comme le salt/nonce sont codés en dur dans generate_vector.py côté
# chiffre-aes-core) — sans quoi chaque exécution du script produirait une
# clé différente et invaliderait le fichier committé. Clé de test
# publique, à n'utiliser dans AUCUN contexte réel.
FIXED_PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
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
ho4arR/g1V+q5W+XNSSbKDwJXpk3j5Q=
-----END PRIVATE KEY-----
"""


def write_vector(name: str, vector: dict):
    os.makedirs(VECTORS_DIR, exist_ok=True)
    path = os.path.join(VECTORS_DIR, f"oaep_{name}.json")
    with open(path, "w") as f:
        json.dump(vector, f, indent=2)
    print(f"oaep_{name} ecrit : {path}")


def generate_positive_vector(name: str, cek: bytes, description: str):
    """`cek` : clé de contenu de 32 octets à sceller/desceller."""
    assert len(cek) == 32, f"cek doit faire 32 octets, obtenu {len(cek)}"

    private_key = load_pem_private_key(FIXED_PRIVATE_KEY_PEM, password=None)
    public_key = private_key.public_key()

    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    wrapped_key = public_key.encrypt(cek, oaep)

    # Auto-vérification avant d'écrire quoi que ce soit : le vecteur généré
    # doit d'abord se redéchiffrer correctement avec cette même
    # implémentation indépendante, sinon il ne vaut rien comme référence
    # pour le côté Rust.
    assert private_key.decrypt(wrapped_key, oaep) == cek

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_spki_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    import hashlib
    fingerprint = hashlib.sha256(public_spki_der).digest()

    vector = {
        "description": description,
        "algorithm": "RSA-4096-OAEP-SHA256 (MGF1-SHA256, label vide)",
        "inputs": {
            "private_key_pkcs8_pem": private_pem.decode(),
            "cek_hex": cek.hex(),
        },
        "expected": {
            "public_key_spki_pem": public_spki_pem.decode(),
            "public_key_fingerprint_sha256_hex": fingerprint.hex(),
            "wrapped_key_hex": wrapped_key.hex(),
        },
    }
    write_vector(name, vector)
    return wrapped_key, cek


def generate_negative_vector_corrupted(name: str, source_wrapped_key: bytes, description: str):
    """Corrompt un octet d'un `wrapped_key_hex` valide déjà généré : le
    descellement DOIT échouer (jamais de panic, jamais de clé incorrecte
    renvoyée silencieusement)."""
    corrupted = bytearray(source_wrapped_key)
    corrupted[0] ^= 0xFF

    vector = {
        "description": description,
        "algorithm": "RSA-4096-OAEP-SHA256 (MGF1-SHA256, label vide)",
        "inputs": {
            "private_key_pkcs8_pem": FIXED_PRIVATE_KEY_PEM.decode(),
            "wrapped_key_hex": bytes(corrupted).hex(),
        },
        "expected": {
            "decrypt_must_fail": True,
        },
    }
    write_vector(name, vector)


def write_fixed_key_pem():
    """Écrit la clé fixe seule (PEM PKCS#8, en clair) dans son propre
    fichier — réutilisée telle quelle par le harnais de fuzzing
    (`fuzz/fuzz_targets/unwrap_key.rs`), qui a besoin d'UNE clé fixe pour
    éviter de regénérer une paire RSA-4096 à chaque itération."""
    os.makedirs(VECTORS_DIR, exist_ok=True)
    path = os.path.join(VECTORS_DIR, "fixed_test_key.pem")
    with open(path, "wb") as f:
        f.write(FIXED_PRIVATE_KEY_PEM)
    print(f"fixed_test_key.pem ecrit : {path}")


def main():
    write_fixed_key_pem()

    # --- oaep_001 : cas nominal --------------------------------------------
    wrapped_001, _ = generate_positive_vector(
        name="001",
        cek=bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        description="Cas nominal : CEK avec octets tous distincts.",
    )

    # --- oaep_002 : cas limite, CEK tout à zéro ----------------------------
    generate_positive_vector(
        name="002",
        cek=bytes(32),
        description="Cas limite : CEK entierement a zero (verifie l'absence de "
                     "traitement special/court-circuit sur cette valeur).",
    )

    # --- oaep_003 : cas limite, CEK tout à 0xFF ----------------------------
    generate_positive_vector(
        name="003",
        cek=bytes([0xFF] * 32),
        description="Cas limite : CEK entierement a 0xFF.",
    )

    # --- oaep_004 : negatif, ciphertext corrompu ---------------------------
    generate_negative_vector_corrupted(
        name="004_corrupted",
        source_wrapped_key=wrapped_001,
        description="Negatif : premier octet du wrapped_key d'oaep_001 "
                     "inverse (XOR 0xFF) - le descellement doit echouer "
                     "proprement, jamais paniquer ni retourner une cle "
                     "incorrecte.",
    )


if __name__ == "__main__":
    main()
