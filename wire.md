# Wire Format for Secure Message Transmission

## Abstract

This document describes the wire format for securely encoding, decoding, encrypting,
and decrypting messages sent over the wire. The wire format is designed to ensure
data integrity, confidentiality, and authenticity. The data structures are encoded
and decoded using MsgPack (message pack) to provide a compact and efficient binary
representation.

## 1. Introduction

The wire format is used to transmit secure messages between services. It includes
mechanisms for signing, encrypting, and validating the integrity of the data. The
format is designed to be stable and interoperable, allowing different versions of
the protocol to coexist.

## 2. Data Structures

### 2.1 Message

The `Message` structure represents the useful data that is sent over the wire. It
includes the payload, optional files, and an optional response.

#### MsgPack Representation

```
Message ::= { "payload": Payload, "files": Files, "response": Response }

Payload ::= binary

Files ::= map<string, File>

Response ::= Encryption | nil
```

### 2.2 File

The `File` structure represents a file that is sent over the wire. It includes
the file data, mode, modification time, and owner.

#### MsgPack Representation

```
File ::= { "data":    FileData,
           "size":    Size,
           "mode":    FileMode,
           "modtime": FileModTime,
           "owner":   Owner
           "uid":     ID
           "group":   Owner
           "gid":     ID
         }

FileData ::= binary

Size ::= int64

FileMode ::= uint32 | nil

FileModTime ::= timestamp | nil

Owner ::= string | nil

ID ::= uint32 | nil
```

### 2.3 Encryption

The `Encryption` structure contains instructions for how to encrypt the response.

#### MsgPack Representation
```
Encryption ::= { "alg": EncryptionAlg, "key": EncryptionKey }

EncryptionAlg ::= string

EncryptionKey ::= string
```

## 3. Encoding and Decoding

The data structures are encoded and decoded using MsgPack. This ensures a
compact and efficient binary representation of the data.

### 3.1 Encoding

To encode a `Message`:

1. Create a `Message` instance with the desired payload, files, and response.
2. Encode the `Message` instance using MsgPack.
3. Create a JWS that includes the `Message`.
4. Compress the resulting JWS using Gzip.

### 3.2 Decoding

To decode a `Message`:

1. Uncompress the data using Gzip.
2. Verify the JWS signature.
3. Extract the payload of the JWS a `Message` instance using MsgPack.

## 4. Encrypting and Decrypting

The encrypted form of the data structures are similar, but the compression steps
happen at different points.

### 4.1 Encrypting

1. Create a `Message` instance with the desired payload, files, and response.
2. Encode the `Message` instance using MsgPack.
3. Compress the resulting binary using Gzip.
4. Create a JWE that includes the compressed data.

### 4.2 Decrypting

1. Decrypt the data of the JWE.
2. Decompress the resulting payload using Gzip.
3. Convert the MsgPack encoded data into a `Message`

## 5. Security Considerations

- **Data Integrity**: The SHA of the data is included in the JWS to ensure that
    the data is not tampered with.
- **Confidentiality**: The `Encryption` structure provides instructions for
    encrypting the response.
- **Authenticity**: The JWS signature ensures that the data is from a trusted source.

## 6. Conclusion

This document describes the wire format for securely transmitting messages between
services. The format ensures data integrity, confidentiality, and authenticity
using MsgPack for encoding and decoding, and JWS for signing. The stable and
interoperable design allows different versions of the protocol to coexist.

## 7. References

- [JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)
- [JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [Message Pack (MsgPack)](https://msgpack.org/)