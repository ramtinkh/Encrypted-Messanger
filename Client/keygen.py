from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def key_gen(username, password):

    pr_key_file = username + ".key"
    # Generate a new private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize the private key to PEM format
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    # Save the serialized private key to a file
    with open(pr_key_file, 'wb') as file_out:
        file_out.write(pem_data)

    plain_pr_key_file = 'plain_' + pr_key_file
    with open(plain_pr_key_file, 'wb') as file_out:
        file_out.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Get the corresponding public key from the private key
    public_key = private_key.public_key()

    # Serialize the public key to PEM format.
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    public_file = username + "public.pem"
    with open(public_file, 'wb') as f:
        f.write(public_key_pem)

def get_public_key(username):
    public_file = username + "public.pem"
    # with open(public_file, 'wb') as f:
    #     f.write(public_key_pem)