"""
DH.py     Ahmed Al Sunbati     Nov 13th, 2025
Description: Helper functions for performing Diffie-Hellman key exchange

Citations: 
"""

import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_pem_public_key,
    ParameterFormat, load_pem_parameters
)
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend



def generate_dh_parameters(generator=2, key_size=2048):
    """
    Generates the public DH parameters (p and g).
    This only needs to be run ONCE by the INITIATOR.
    """
    return dh.generate_parameters(generator=generator, key_size=key_size)

def serialize_parameters(parameters):
    """Converts the DH parameters (p, g) object to bytes for sending."""
    return parameters.parameter_bytes(
        Encoding.PEM,
        ParameterFormat.PKCS3
    )

def deserialize_parameters_bytes(parameter_bytes):
    """Converts received bytes back into a DH parameters object."""
    return load_pem_parameters(
        parameter_bytes,
        backend=default_backend()
    )

def generate_dh_keys(parameters):
    """
    Generates a private/public key pair from the shared parameters.
    Both parties run this.
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return public_key, private_key

def serialize_public_key(public_key):
    """Converts a public key object to bytes for sending."""
    return public_key.public_bytes(
        Encoding.PEM,
        PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key_bytes(public_key_bytes):
    """Converts received bytes back into a public key object."""
    return load_pem_public_key(public_key_bytes)

def calculate_shared_secret(our_private_key, received_public_key):
    """Calculates the shared secret (the "crude oil")."""
    return our_private_key.exchange(received_public_key)

def get_derived_key(shared_secret):
    """
    "Refines" the shared secret into a 32-byte AES key using HKDF.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'video-call-encryption'
    ).derive(shared_secret)


def encrypt(derived_key, data):
    """
    Encrypts data using the derived key (AES-GCM).
    Returns a single byte string: [ 12-byte NONCE ] + [ CIPHERTEXT ]
    """
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt(derived_key, encrypted_data):
    """
    Decrypts data using the derived key.
    Parses the [ NONCE ] + [ CIPHERTEXT ] format.
    Returns the decrypted data, or None if integrity check fails.
    """
    if len(encrypted_data) < 13:
        return None # Not long enough to even have a nonce

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    aesgcm = AESGCM(derived_key)
    
    try:
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_data
    except InvalidTag:
        print("Decryption failed: Packet was corrupt or tampered with.")
        return None