<h1 align="center">
Diffie Hellman Key Exchange with OpenSSL 🔑
</h1>

## Summary
- [Set Up](#set-up-)
- [Create your public and private key](#create-your-public-and-private-key-)
- [Cipher a file with your public key](#cipher-a-message-using-the-session-key-)
- [Decipher a file with your private key and the other public key](#decipher-the-message-using-the-session-key-)

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

## Decipher the message using the session key🔓
The session key is generated from:
- Your private key (which in the cryptography library needs your public key for recreating the DHPrivateKey object).
- The other entity public key.

Knowing this, execute:
```
    $ python decipher.py
```
