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


def save_key_to_file(key: bytes, file: str):
    with open(file, 'wb') as f:
        f.write(key)


def cypher_data(pem: str, my_public_key: str, my_private_key: str, other_public_key: str, message: str, output: str):
    with open(pem, 'rb') as file:
        parameters: dh.DHParameters = load_pem_parameters(file.read())
        params_numbers = parameters.parameter_numbers()

        private_key: dh.DHPrivateKey = get_private_key(params_numbers, my_public_key, my_private_key)
        public_key_other: dh.DHPublicKey = get_public_key(params_numbers, other_public_key)
        shared_key = private_key.exchange(public_key_other)

        cipher = Cipher(algorithm=AES256(shared_key[:32]), mode=CBC(bytearray(16)))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(256).padder()
        message: bytes = message.encode("utf-8")
        padded_data = padder.update(message) + padder.finalize()
        message_encripted = encryptor.update(padded_data) + encryptor.finalize()
        message_base64 = base64.encodebytes(message_encripted)
        save_key_to_file(message_base64, output)


if __name__ == "__main__":
    # Argument Parser
    parser = argparse.ArgumentParser(prog='cipher.py', description='Cipher a message using the session key')
    parser.add_argument('-p', '--pem')
    parser.add_argument('-mprvk', '--my-private-key')
    parser.add_argument('-mpubk', '--my-public-key')
    parser.add_argument('-opubk', '--other-public-key')
    parser.add_argument('-m', '--message')
    parser.add_argument('-o', '--output')
    args = parser.parse_args()

    # Default values of arguments
    pem_file = args.pem if args.pem else "data/dhpar.pem"
    my_private_key_file = args.my_private_key if args.my_private_key else "old_private_key.asc"
    my_public_key_file = args.my_public_key if args.my_public_key else "old_public_key.asc"
    other_public_key_file = args.other_public_key if args.other_public_key else "data/pubA.asc"
    message = args.message if args.message else "Pablo Fraile Alonso"
    output = args.output if args.output else "ciphertext.b64"

    # Cipher
    cypher_data(pem_file, my_public_key_file, my_private_key_file, other_public_key_file, message, output)
