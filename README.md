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
1. Enter the required information (output folder, file name, subject, SAN, validity period, etc.).
2. Click the "Create Self-Signed Certificate" button to generate the certificate and private key.
   - To use an existing private key, check "Use existing private key if available".
3. You can also create CRLs and revoke certificates from the GUI.

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