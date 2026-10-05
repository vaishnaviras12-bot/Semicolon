from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ecdsa_private = ec.generate_private_key(ec.SECP256R1())
x25519_private = x25519.X25519PrivateKey.generate()

aes_key = b"0" * 32
cipher = Cipher(algorithms.AES(aes_key), modes.GCM(b"1" * 12))
h = hmac.HMAC(b"2" * 32, hashes.SHA256())

legacy_hash = hashes.SHA1()
modern_hash = hashes.SHA256()

# Synthetic references for ECDAT detection:
# RSA-2048, ECDSA P-256, ECDH, X25519, AES-256-GCM, HMAC-SHA256, SHA-1, SHA-256
