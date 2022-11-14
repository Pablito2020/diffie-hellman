import argparse
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.asymmetric import dh


def save_key_to_file(key: int, file: str):
    with open(file, 'w', encoding="utf-8") as f:
        f.write(repr(key))


def create_keys(pem_file: str, private_key_file: str, public_key_file: str):
    with open(pem_file, 'rb') as file:
        parameters: dh.DHParameters = load_pem_parameters(file.read())
        params_numbers = parameters.parameter_numbers()
        print(f"Generator value of file: {file.name} is:")
        print(params_numbers.g)
        print(f"\nPrime value of file: {file.name} is:")
        print(params_numbers.p)
        private_key = parameters.generate_private_key()
        private_number = private_key.private_numbers()
        print("Saving private key....")
        save_key_to_file(private_number.x, private_key_file)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        print("Saving public key....")
        save_key_to_file(public_numbers.y, public_key_file)


if __name__ == "__main__":
    # Argument Parser
    parser = argparse.ArgumentParser(prog='create_keys.py', description='Create public and private keys from a Diffie-Hellman-Parameters file')
    parser.add_argument('-p', '--pem')
    parser.add_argument('-opriv', '--output-private-key')
    parser.add_argument('-opub', '--output-public-key')
    args = parser.parse_args()

    # Generate keys
    pem_file = args.pem if args.pem else "data/dhpar.pem"
    private_key_file = args.output_private_key if args.output_private_key else "privB.asc"
    public_key_file = args.output_public_key if args.output_public_key else "pubB.asc"
    create_keys(pem_file, private_key_file, public_key_file)
