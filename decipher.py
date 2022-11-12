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


def get_bytes_file(file: str) -> bytes:
    with open(file, 'rb') as f:
        return base64.decodebytes(f.read())


with open("data/dhpar.pem", 'rb') as file:
    parameters: dh.DHParameters = load_pem_parameters(file.read())
    params_numbers = parameters.parameter_numbers()

    my_private_key: dh.DHPrivateKey = get_private_key(params_numbers, "public_key.asc", "private_key.asc")
    public_key_cesar: dh.DHPublicKey = get_public_key(params_numbers, "old_public_key.asc")
    shared_key = my_private_key.exchange(public_key_cesar)

    cipher = Cipher(algorithm=AES256(shared_key[:32]), mode=CBC(bytearray(16)))
    decryptor = cipher.decryptor()
    bytes_file = get_bytes_file("ciphertext.b64")
    message = decryptor.update(bytes_file) + decryptor.finalize()
    unpadding = padding.PKCS7(128).unpadder()
    message_without_padding = unpadding.update(message) + unpadding.finalize()
    print(f"Message is: {message_without_padding.decode('utf-8')}")
