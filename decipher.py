from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES256
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import padding
import base64
import argparse


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


def decypher_data(pem: str, my_public_key: str, my_private_key: str, other_public_key: str, message_file: str):
    with open(pem, 'rb') as file:
        parameters: dh.DHParameters = load_pem_parameters(file.read())
        params_numbers = parameters.parameter_numbers()

        private_key: dh.DHPrivateKey = get_private_key(params_numbers, my_public_key, my_private_key)
        public_key_other: dh.DHPublicKey = get_public_key(params_numbers, other_public_key)
        shared_key = private_key.exchange(public_key_other)

        cipher = Cipher(algorithm=AES256(shared_key[:32]), mode=CBC(bytearray(16)))
        decryptor = cipher.decryptor()
        bytes_file = get_bytes_file(message_file)
        message = decryptor.update(bytes_file) + decryptor.finalize()
        unpadding = padding.PKCS7(128).unpadder()
        message_without_padding = unpadding.update(message) + unpadding.finalize()
        print(f"Message is: {message_without_padding.decode('utf-8')}")


if __name__ == "__main__":
    # Argument Parser
    parser = argparse.ArgumentParser(prog='cipher.py', description='Cipher a message using the session key')
    parser.add_argument('-p', '--pem')
    parser.add_argument('-mprvk', '--my-private-key')
    parser.add_argument('-mpubk', '--my-public-key')
    parser.add_argument('-opubk', '--other-public-key')
    parser.add_argument('-f', '--message-file')
    args = parser.parse_args()

    # Default values of arguments
    pem_file = args.pem if args.pem else "data/dhpar.pem"
    my_private_key_file = args.my_private_key if args.my_private_key else "privA.asc"
    my_public_key_file = args.my_public_key if args.my_public_key else "pubA.asc"
    other_public_key_file = args.other_public_key if args.other_public_key else "pubB.asc"
    message_file = args.message_file if args.message_file else "ciphertext.b64"

    # Cipher
    decypher_data(pem_file, my_public_key_file, my_private_key_file, other_public_key_file, message_file)
