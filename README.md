# OpcUaCertMaker

## Overview
OpcUaCertMaker is a WPF application for easily creating and managing self-signed certificates and CRLs (Certificate Revocation Lists) for OPC UA servers/clients via a graphical user interface.

## Features
- Create new private keys and certificates (supports PEM/PFX formats)
- Re-issue certificates using an existing private key
- Create CRLs (Certificate Revocation Lists)
- Revoke certificates (add to CRL)
- Specify output folder for certificates and private keys
- Set subject information (CN, O, OU, L, ST, C) and SANs (DNS, URI, IP)
- Specify validity period

## Usage

### OPC UA Certificate Requirements
OPC UA clients check if the ApplicationUrl matches the URI in the Subject Alternative Name (SAN) of the certificate. To ensure your certificate is valid for OPC UA, set the ApplicationUrl and the SAN URI to the same value. Additionally, the DNS name or IP address in the SAN must match the device where the server or client is running. Please set the correct DNS Name or IP Address in the SAN fields. If there are multiple access points, you can specify multiple values separated by commas.

### Creating a Self-Signed Certificate
To create a self-signed certificate, click the "Generate by Self" button in the "Certification Generation" section. The generated files will follow the selected Private Key Format (PEM or PFX) and will be saved in the Output Folder with the specified File Name.

### Using an Existing Private Key
If you check "Use existing private key if available", the certificate will be generated using the existing private key instead of creating a new one. This is useful when you need to revoke a certificate later using a CRL.

### Creating a CRL (Certificate Revocation List)
To create a CRL, set the private key and certificate in the "Root CA" section, then click the "Clear" button in the "CRL" section. Even for self-signed certificates, you need to set the key and certificate in "Root CA". The generated CRL file will be saved in the Output Folder as File Name + ".crl".

### Revoking a Certificate
To revoke a certificate, set the private key and certificate in the "Root CA" section, then click the "Revoke" button in the "CRL" section. The CRL will be generated and the specified certificate will be added to the revocation list.

### Creating an Intermediate Certificate
To create an intermediate certificate, set the private key and certificate in the "Root CA" section, then click the "Generate by CA" button in the "Certification Generation" section. Note: If the Subject CN of the Root CA and the intermediate certificate are the same, the issuer and subject of the generated certificate will match, making it indistinguishable from a self-signed certificate. Therefore, make sure the Subject CNs are different. The private key and certificate set in "Root CA" can be those created as a self-signed certificate.

## Development Environment
- .NET 8
- C# 12
- WPF
- Prism
- BouncyCastle

## Build Instructions
Open the solution in Visual Studio 2022 or later and build the project.

## License
MIT License

## Author
bamchoh

---
For details, please refer to the source code and UI.