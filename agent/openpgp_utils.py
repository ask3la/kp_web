import json
import warnings
from pathlib import Path

import pgpy
from pgpy.constants import CompressionAlgorithm, HashAlgorithm, KeyFlags, PubKeyAlgorithm, SymmetricKeyAlgorithm

warnings.filterwarnings("ignore", message=".*TripleDES.*", category=Warning)

def ensure_agent_keypair(private_path: Path, public_path: Path) -> None:
    private_path.parent.mkdir(parents=True, exist_ok=True)
    if private_path.exists() and public_path.exists():
        return
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("AlphaTest Storage Agent", email="agent@alpha.local")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.Uncompressed],
    )
    private_path.write_text(str(key), encoding="utf-8")
    public_path.write_text(str(key.pubkey), encoding="utf-8")


def load_key(path: Path) -> pgpy.PGPKey:
    key, _ = pgpy.PGPKey.from_blob(path.read_text(encoding="utf-8"))
    return key


def encrypt_json_for_public_key(public_key_asc: str, payload: dict) -> str:
    key, _ = pgpy.PGPKey.from_blob(public_key_asc)
    msg = pgpy.PGPMessage.new(json.dumps(payload, ensure_ascii=False))
    # Let recipient key preferences choose compression to avoid preference mismatch warnings.
    encrypted = key.encrypt(msg, cipher=SymmetricKeyAlgorithm.AES256)
    return str(encrypted)


def decrypt_json_with_private_key(private_key: pgpy.PGPKey, encrypted_payload: str) -> dict:
    enc = pgpy.PGPMessage.from_blob(encrypted_payload)
    dec = private_key.decrypt(enc)
    return json.loads(dec.message)
