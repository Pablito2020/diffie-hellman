<h1 align="center">
Diffie Hellman Key Exchange with OpenSSL 🔑
</h1>

## Summary
- [Set Up](#set-up-)
- [Files](#files-)
- [Create your public and private key](#create-your-public-and-private-key-)
- [Cipher a message with the session key](#cipher-a-message-using-the-session-key-)
- [Decipher a message with the session key](#decipher-the-message-using-the-session-key-)
- [Running the tests](#running-the-tests-)

## Set up 📦

### Create and enable a virtual environment

```
    $ pip install virtualenv
    $ python -m venv venv
    $ source venv/bin/activate
```

### Install the dependencies

```
    $ pip install -r requirements.txt
```

## Files 📁
The assignment specifies that the following files must be submitted:
- pubB.asc (it's inside data/pubB.asc)
- ciphertext.b64 (it's inside data/ciphertext.b64)

## Create your public and private key 🔑
For generating a public and private key, execute the following command:

```
    $ python create_keys.py
```
The public key will be saved on public_key.asc, and the private key will be saved on private_key.asc

## Cipher a message using the session key 🔒
The session key is generated from:
- Your private key (which in the cryptography library needs your public key for recreating the DHPrivateKey object).
- The other entity public key.

Knowing this, execute:
```
    $ python cipher.py
```

## Decipher the message using the session key 🔓
The session key is generated from:
- Your private key (which in the cryptography library needs your public key for recreating the DHPrivateKey object).
- The other entity public key.

Knowing this, execute:
```
    $ python decipher.py
```

## Running the tests 🧪
I've made one test that does the following:
- Generates private and public keys for A
- Generates private and public keys for B
- Ciphers a message from A and saves it to a file.
- B deciphers the message from A.
- Assert that the message is the same.

For running this test execute:

```
    $ ./test/run.sh
```
