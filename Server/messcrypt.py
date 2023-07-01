from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, utils
from cryptography.hazmat.primitives.asymmetric import padding

def encrypt_message(message, public_key):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

def decrypt_message(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message

def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(utils.hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.hashes.SHA256()
    )
    return signature

def verify_message(signature, message, public_key):
    verified = public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(utils.hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.hashes.SHA256()
    )
    return verified