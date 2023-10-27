# Kernel Keymanager Service

## Overview

All cryptograhpic keys in MOSIP are generated and maintained in KeyManager Service.
APIs available to perform all cryptograhpic operations like encryption/decryption, signing/verification, trust path validation, ZK Encryption.

## APIs
### Client Crypto
1. APIs to do encryption/decryption & sign/verify using TPM key

### Crypto Manager
1. APIs to perform encryption/decryption using RSA OAEP padding algorithm
1. APIS to do encryption/decryption using PIN based encryption and PBKDF2WithHmacSHA512 algorithm

### Keymanager 
1. APIs for key generation, update of MOSIP certificates, upload partner certificates
1. Encryption keys will be auto generated 

### Keymigrator
1. APIs to perform key migration from one HSM to another.

### Partner Certificate Management
1. APIs for upload of CA/Sub CA certificate, upload of Partner Certificates, trust path validation 

### Signature
1. APIs for JWS signature & verification

### ZKEncryption
1. APIs for ZK encryption/decryption & key sharing between Keymanager & IDA service.
