import json
import warnings
from pathlib import Path

import pgpy
from pgpy.constants import CompressionAlgorithm, HashAlgorithm, KeyFlags, PubKeyAlgorithm, SymmetricKeyAlgorithm

from .config import SERVER_PRIVATE_KEY_PATH, SERVER_PUBLIC_KEY_PATH

warnings.filterwarnings("ignore", message=".*TripleDES.*", category=Warning)


def ensure_server_keypair() -> None:
    SERVER_PRIVATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SERVER_PRIVATE_KEY_PATH.exists() and SERVER_PUBLIC_KEY_PATH.exists():
        return

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("CoStor Central Server", email="central@costor.local")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.Uncompressed],
    )
    SERVER_PRIVATE_KEY_PATH.write_text(str(key), encoding="utf-8")
    SERVER_PUBLIC_KEY_PATH.write_text(str(key.pubkey), encoding="utf-8")


def load_server_private_key() -> pgpy.PGPKey:
    ensure_server_keypair()
    key, _ = pgpy.PGPKey.from_blob(SERVER_PRIVATE_KEY_PATH.read_text(encoding="utf-8"))
    return key


def load_server_public_key() -> pgpy.PGPKey:
    ensure_server_keypair()
    key, _ = pgpy.PGPKey.from_blob(SERVER_PUBLIC_KEY_PATH.read_text(encoding="utf-8"))
    return key


def encrypt_json_for_public_key(public_key_asc: str, payload: dict) -> str:
    key, _ = pgpy.PGPKey.from_blob(public_key_asc)
    msg = pgpy.PGPMessage.new(json.dumps(payload, ensure_ascii=False))
    encrypted = key.encrypt(msg, cipher=SymmetricKeyAlgorithm.AES256)
    return str(encrypted)


def decrypt_json_with_private_key(private_key: pgpy.PGPKey, encrypted_payload: str) -> dict:
    enc = pgpy.PGPMessage.from_blob(encrypted_payload)
    dec = private_key.decrypt(enc)
    return json.loads(dec.message)


def server_public_key_text() -> str:
    ensure_server_keypair()
    return SERVER_PUBLIC_KEY_PATH.read_text(encoding="utf-8")
