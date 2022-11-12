from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import padding
import base64


def get_public_key(params_numbers: dh.DHParameterNumbers, file: str) -> dh.DHPublicKey:
    with open(file, 'r', encoding="ascii") as f:
        y = int(f.read())
        peer_public_numbers = dh.DHPublicNumbers(y, params_numbers)
        return peer_public_numbers.public_key()


def get_private_key(params_numbers: dh.DHParameterNumbers, file_pub: str, file_priv: str) -> dh.DHPrivateKey:
    public_key = get_public_key(params_numbers, file_pub)
    with open(file_priv, 'r', encoding="ascii") as f:
        x = int(f.read())
        return dh.DHPrivateNumbers(x, public_key.public_numbers()).private_key()


def save_key_to_file(key: bytes, file: str):
    with open(file, 'wb') as f:
        f.write(key)


with open("data/dhpar.pem", 'rb') as file:
    parameters: dh.DHParameters = load_pem_parameters(file.read())
    params_numbers = parameters.parameter_numbers()

    my_private_key: dh.DHPrivateKey = get_private_key(params_numbers, "old_public_key.asc", "old_private_key.asc")
    public_key_cesar: dh.DHPublicKey = get_public_key(params_numbers, "public_key.asc")
    shared_key = my_private_key.exchange(public_key_cesar)

    cipher = Cipher(algorithm=AES256(shared_key[:32]), mode=CBC(bytearray(16)))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(256).padder()
    message: bytes = 'Pablo Fraile Alonso'.encode("utf-8")
    padded_data = padder.update(message) + padder.finalize()
    message_encripted = encryptor.update(padded_data) + encryptor.finalize()
    message_base64 = base64.encodebytes(message_encripted)
    save_key_to_file(message_base64, "ciphertext.b64")
