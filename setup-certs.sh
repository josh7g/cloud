#!/bin/bash
set -e

# Create PostgreSQL certificates directory
mkdir -p postgres-certs

# Generate a self-signed certificate
openssl req -new -x509 -days 365 -nodes \
  -out postgres-certs/server.crt \
  -keyout postgres-certs/server.key \
  -subj "/CN=db"

# Set proper permissions
chmod 600 postgres-certs/server.key
chmod 644 postgres-certs/server.crt