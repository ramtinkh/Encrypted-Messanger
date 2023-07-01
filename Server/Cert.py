import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.x509.oid import NameOID
from cryptography import x509
import datetime
import json

def generate_server_cert():
    password = input("Enter Password:")
    # password = "1234"
    if os.stat('server.key').st_size == 0:
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
        with open('server.key', 'wb') as file_out:
            file_out.write(pem_data)


        with open('plain_server.key', 'wb') as file_out:
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


        with open('server_public_key.pem', 'wb') as f:
            f.write(public_key_pem)
    else:
        with open('server.key', 'rb') as file_in:
            encrypted_private_key = file_in.read()
        try:
            # Deserialize and decrypt the private key
            private_key = serialization.load_pem_private_key(
                encrypted_private_key,
                password=password.encode(),
                backend=default_backend()
                )

            with open('plain_server.key', 'wb') as file_out:
                file_out.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            return private_key
        except:
            print("Wrong Password")
            return generate_server_cert()

    # Generate a certificate signing request (CSR)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com")
    ])).sign(private_key, hashes.SHA256())

    # Save the CSR to a file (not needed for self-signed certificate)
    with open("server.csr", "wb") as csr_file:
        csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

    # Generate a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com")
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())

    # Save the self-signed certificate to a file
    with open("server.crt", "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

