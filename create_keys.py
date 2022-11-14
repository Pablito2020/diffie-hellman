from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.asymmetric import dh


def save_number_to_file(data: int, file: str):
    with open(file, 'w', encoding="utf-8") as f:
        f.write(repr(data))


with open("data/dhpar.pem", 'rb') as file:
    parameters: dh.DHParameters = load_pem_parameters(file.read())
    params_numbers = parameters.parameter_numbers()
    print(f"Generator value of file: {file.name} is:")
    print(params_numbers.g)
    print(f"\nPrime value of file: {file.name} is:")
    print(params_numbers.p)

    private_key = parameters.generate_private_key()
    private_number = private_key.private_numbers()
    print("Saving private key....")
    save_number_to_file(private_number.x, "private_key.asc")

    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()
    print("Saving public key....")
    save_number_to_file(public_numbers.y, "public_key.asc")
