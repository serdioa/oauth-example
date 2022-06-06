#!/bin/bash

# Clean up
rm *.pem *.crt

# (1)
# Generate a public and private keys (RSA, 2048 bit), valid for 720 days.
# You will be prompted to enter a password for the private key.
openssl req -newkey rsa:2048 -subj "/CN=Panther Trading/O=Societe Generale SE/C=DE" -days 720 \
    -x509 -outform PEM -keyout rsa-2048-sample.pem -out rsa-2048-sample.crt

# (2)
# Import the generated keys into a certificate store.
# You will be prompted to enther a password for the private key you are importing.
# Then you will be prompted to enter a password for the keystore you are importing the key in.
openssl pkcs12 -export -inkey rsa-2048-sample.pem -in rsa-2048-sample.crt \
    -name oauth202206 -out oauth.pkx

# (3)
# List available keys.
keytool -list -keystore oauth.pkx
