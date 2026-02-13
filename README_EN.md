# kamusm-zd-rs

> 🇹🇷 [Türkçe](README.md)
> 
An RFC 3161 compliant Kamu SM (Turkish Public CA) timestamp client written in Rust, supporting Kamu SM's custom authentication protocol and compatible with the official Java client.

## Table of Contents

- [kamusm-zd-rs](#kamusm-zd-rs)
  - [Table of Contents](#table-of-contents)
  - [Protocol Architecture](#protocol-architecture)
    - [Identity Header](#identity-header)
  - [Cryptography References](#cryptography-references)
  - [Requirements](#requirements)
  - [Installation](#installation)
    - [Building from Source](#building-from-source)
    - [Running Directly](#running-directly)
  - [Usage](#usage)
    - [Basic Command Structure](#basic-command-structure)
    - [Requesting a Timestamp](#requesting-a-timestamp)
      - [Timestamp for a file](#timestamp-for-a-file)
      - [Timestamp for a hex digest](#timestamp-for-a-hex-digest)
    - [Checking Credits](#checking-credits)
    - [Generating an Identity Header](#generating-an-identity-header)
  - [Configuration Options](#configuration-options)
    - [Common Parameters](#common-parameters)
    - [Send Command Parameters](#send-command-parameters)
    - [Output Files](#output-files)
  - [Technical Implementation](#technical-implementation)
    - [Cryptographic Stack](#cryptographic-stack)
    - [MessageImprint Generation](#messageimprint-generation)
    - [Error Handling](#error-handling)
    - [HTTP Request Format](#http-request-format)
  - [Examples](#examples)
    - [Successful Timestamp Request](#successful-timestamp-request)
    - [Verification with the Official Client](#verification-with-the-official-client)
    - [Credit Check](#credit-check)
    - [Error Case](#error-case)
  - [Common Errors](#common-errors)
  - [Implementation Notes](#implementation-notes)
    - [Dependencies](#dependencies)

## Protocol Architecture

Kamu SM timestamp servers use the standard RFC 3161 TimeStampReq/TimeStampResp structure but require a custom `identity` header for authentication:

- **HTTP**: `POST /` with `application/timestamp-query`
- **Body**: RFC 3161 TimeStampReq (ASN.1 DER)
- **Authentication**: User authentication via the `identity` header
- **Response**: PKCS#7 SignedData with certificate

### Identity Header

`identity` is the BigInteger hex representation of the DER encoding of the following ASN.1 structure:

```asn1
ESYAReqEx ::= SEQUENCE {
    userid                 INTEGER,
    salt                   OCTET STRING (16 bytes),
    iterationCount         INTEGER (100),
    iv                     OCTET STRING (16 bytes, same as salt),
    encryptedMessageImprint OCTET STRING
}
```

**Encryption Flow:**
1. 16-byte random value → used as both salt and IV
2. PBKDF2-HMAC-SHA256(password, salt, 100 iterations) → 32-byte AES key
3. AES-256-CBC(messageImprint, key, iv) + PKCS#7 padding → encrypted data
4. ASN.1 structure → DER encoding → BigInteger → hex string

This prevents replay attacks by using a different salt/IV for each request.

## Cryptography References

- **RFC 3161**: Time-Stamp Protocol ([RFC 3161](https://tools.ietf.org/html/rfc3161))
- **PKCS#7**: Public Key Cryptography Standards #7 ([RFC 2315](https://tools.ietf.org/html/rfc2315))
- **PKCS#7 SignedData**: Digitally signed data structure ([RFC 2315 Section 9.1](https://tools.ietf.org/html/rfc2315#section-9.1))
- **ASN.1**: Abstract Syntax Notation One - Data structure description notation ([ITU-T X.680](https://www.itu.int/rec/T-REC-X.680/))
- **DER**: Distinguished Encoding Rules - ASN.1 binary encoding rules ([ITU-T X.690](https://www.itu.int/rec/T-REC-X.690/))
- **PBKDF2**: Password-Based Key Derivation Function 2 ([RFC 2898 Section 5.2](https://tools.ietf.org/html/rfc2898#section-5.2))
- **HMAC**: Hash-based Message Authentication Code ([RFC 2104](https://tools.ietf.org/html/rfc2104))
- **AES-256**: Advanced Encryption Standard, 256-bit key length ([FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final))
- **CBC**: Cipher Block Chaining mode ([Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)))

## Requirements

- Rust (tested with 1.85)
- Cargo
- A valid Kamu SM user account (customer ID and password)
- Internet connection

## Installation

### Building from Source

```bash
# Clone the repository
git clone https://github.com/omerbustun/kamusm-zd-rs.git
cd kamusm-zd-rs

# Build
cargo build --release

# The executable will be created in target/release/
```

### Running Directly

```bash
# Run in debug mode
cargo run -- --help

# Run in release mode
cargo run --release -- --help
```

## Usage

### Basic Command Structure

```bash
kamusm-zd-rs <COMMAND> [OPTIONS]
```

### Requesting a Timestamp

#### Timestamp for a file

```bash
# SHA256 (recommended/default)
kamusm-zd-rs send \
    --host "http://zd.kamusm.gov.tr" \
    --customer-id 123 \
    --password "password" \
    --file document.txt \
    --hash sha256

# SHA1
kamusm-zd-rs send \
    --host "http://zd.kamusm.gov.tr" \
    --customer-id 123 \
    --password "password" \
    --file document.pdf \
    --hash sha1
```

#### Timestamp for a hex digest

```bash
kamusm-zd-rs send \
    --host "http://zd.kamusm.gov.tr" \
    --customer-id 123 \
    --password "password" \
    --digest-hex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
    --hash sha256
```

### Checking Credits

```bash
kamusm-zd-rs credits \
    --host "http://zd.kamusm.gov.tr" \
    --customer-id 123 \
    --password "password"
```

### Generating an Identity Header

```bash
# With a hex digest
kamusm-zd-rs identity \
    --customer-id 123 \
    --password "password" \
    --digest-hex "abc123..."

# With a timestamp (for credit checks)
kamusm-zd-rs identity \
    --customer-id 123 \
    --password "password" \
    --timestamp 1635724800000
```

## Configuration Options

### Common Parameters

- `--host`: Kamu SM timestamp server address
- `--customer-id`: Customer ID number
- `--password`: Customer password
- `--iterations`: PBKDF2 iteration count (default: 100)

### Send Command Parameters

- `--file`: Path to the file to be timestamped
- `--digest-hex`: Hash value directly in hex format
- `--hash`: Hash algorithm (`sha1` or `sha256`, default: `sha256`)

### Output Files

- File-based operations: `{filename}_zd.der`
- Hex digest operations: `zd_{timestamp}.der`
- Output files are in PKCS#7 SignedData format

## Technical Implementation

### Cryptographic Stack
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100 iterations, 32-byte key)
- **Symmetric Encryption**: AES-256-CBC + PKCS#7 padding
- **ASN.1 Processing**: DER encoding/decoding
- **Hash Algorithms**: SHA1/SHA256 with OIDs, RFC 3161 compliant

### MessageImprint Generation
- **Timestamp Request**: File/data hash (SHA1/SHA256)
- **Credit Check**: SHA1(customerID + timestamp_millis)
- **Authentication**: In all cases, the relevant hash is encrypted and sent in the identity header

### Error Handling
Kamu SM returns standard HTTP 200 for errors but includes error messages within the ASN.1 structure.
The client looks for the PKCS#7 SignedData OID (`1.2.840.113549.1.7.2`):
- **Found**: Valid timestamp, PKCS#7 is processed
- **Not found**: ASN.1 is parsed to extract error messages from UTF8String/PrintableString fields

### HTTP Request Format
```http
POST / HTTP/1.1
Host: zd.kamusm.gov.tr
Content-Type: application/timestamp-query
User-Agent: kamusm-zd-rs
identity: <hex_encoded_ESYAReqEx>
Cache-Control: no-cache
Pragma: no-cache
Content-Length: <der_length>

<RFC3161_TimeStampReq_DER>
```

## Examples

### Successful Timestamp Request

```bash
$ kamusm-zd-rs send --host "http://zd.kamusm.gov.tr" --customer-id 123 --password "password" --file test.txt
Response status: 200 OK
Extracted PKCS#7 SignedData saved to test_zd.der
```

### Verification with the Official Client

You can verify timestamps using Kamu SM's official Java console client:

**Download**: [Kamu SM Software Platform - Zamane](https://yazilim.kamusm.gov.tr/?q=tr/content/zamane)

```bash
$ java -jar tss-client-console-3.1.30.jar -c test.txt test_zd.der
[2025-Sep-27 16:04:45,054 PM] [INFO ] : File timestamp verification will be performed.
[2025-Sep-27 16:04:45,093 PM] [INFO ] : Timestamp is valid, file has not been modified.
```

### Credit Check

```bash
$ kamusm-zd-rs credits --host "http://zd.kamusm.gov.tr" --customer-id 123 --password "password"
Response status: 200 OK
Remaining timestamp credits: 847
```

### Error Case

```bash
$ kamusm-zd-rs send --host "http://zd.kamusm.gov.tr" --customer-id 999 --password "wrong"
Response status: 200 OK
Error response received (HTTP 200 OK)
Error messages:
  User 999 is not known
```

## Common Errors

**"Account could not be authenticated"**
- Incorrect user password

**"User is not known"**
- Customer ID not found
- Wrong customer number

**Connection errors**
- Check the server address
- Check your internet connection
- Check firewall settings

## Implementation Notes

### Dependencies
- **yasna**: ASN.1 DER encoding/decoding (ESYAReqEx, TimeStampReq generation)
- **aes + cbc**: AES-256-CBC implementation (identity encryption)
- **pbkdf2 + hmac**: Key derivation (PBKDF2-HMAC-SHA256)
- **reqwest**: HTTP client (rustls-tls backend, suitable for blocking support/async wrapper)
- **num-bigint**: Java BigInteger.toString(16) compatibility
