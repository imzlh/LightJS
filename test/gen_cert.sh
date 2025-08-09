#!/bin/bash

# Generate self-signed certificate for testing TLS server

# Generate private key
openssl genrsa -out server.key 2048

# Create certificate signing request
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"

# Generate self-signed certificate
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# Clean up CSR
rm server.csr

echo "Self-signed certificate generated:"
echo "Private key: server.key"
echo "Certificate: server.crt"
