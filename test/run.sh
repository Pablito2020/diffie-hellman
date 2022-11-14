#!/bin/bash

# Delete old files (just in case)
rm test/*.asc
rm test/*.b64

# Generate public and private keys for A and B
python create_keys.py  -p data/dhpar.pem -opriv test/priv_key_a.asc -opub test/pub_key_a.asc
python create_keys.py  -p data/dhpar.pem -opriv test/priv_key_b.asc -opub test/pub_key_b.asc

# A cyphers the message 'Pablo Fraile Alonso' to test/ciphertext.b64
python cipher.py  -p data/dhpar.pem -mprvk test/priv_key_a.asc -mpubk test/pub_key_a.asc -opubk test/pub_key_b.asc -m "Pablo Fraile Alonso" -o test/ciphertext.b64

# B deciphers the message of test/ciphertext.b64
message=$(python decipher.py  -p data/dhpar.pem -mprvk test/priv_key_b.asc -mpubk test/pub_key_b.asc -opubk test/pub_key_a.asc -f test/ciphertext.b64)

if [ "$message" = "Message is: Pablo Fraile Alonso" ];then
    echo -e "\n\t\e[0;32mTests passed! :) \e[00m"
else
    echo -e "\n\t\e[00;31mTests not passing :(. Message of decrypt is: $message \e[00m"
fi

# Delete test files
rm test/*.asc
rm test/*.b64
