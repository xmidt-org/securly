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

### 2.1 Outer

The `Outer` structure is the top-level container for the wire payload. It contains
the signed JSON Web Signature (JWS) and the actual data being transmitted.

#### MsgPack Representation

```
Outer ::= { "jws":  JWS,
            "data": Data }

JWS ::= string

Data ::= binary
```

### 2.2 Inner

The `Inner` structure represents the JWS payload over the wire.  It includes the
SHA algorithm and SHA of the binary data from the `Inner` structure.

#### MsgPack Representation

```
Inner ::= { "alg": Algorithm,
            "sha": SHA }

Algorithm ::= string

SHA ::= binary
```

### 2.2 Message

The `Message` structure represents the useful data that is sent over the wire. It includes the payload, optional files, and an optional response.

#### MsgPack Representation

```
Message ::= { "payload": Payload, "files": Files, "response": Response }

Payload ::= binary

Files ::= map<string, File>

Response ::= Encryption | nil
```

### 2.3 File

The `File` structure represents a file that is sent over the wire. It includes the file data, mode, modification time, and owner.

#### MsgPack Representation

```
File ::= { "data":    FileData,
           "mode":    FileMode,
           "modtime": FileModTime,
           "owner":   Owner
           "uid":     ID
           "group":   Owner
           "gid":     ID
         }

FileData ::= binary

FileMode ::= uint32 | nil

FileModTime ::= timestamp | nil

Owner ::= string | nil

ID ::= uint32 | nil
```

### 2.4 Encryption

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
3. Compute the SHA of the encoded data.
4. Create a JWS that includes the SHA of the data.
5. Create an `Outer` instance with the JWS and the encoded data.
6. Encode the `Outer` instance using MsgPack.

### 3.2 Decoding

To decode an `Outer`:

1. Decode the `Outer` instance using MsgPack.
2. Verify the JWS signature.
3. Compute the SHA of the data and compare it with the SHA in the JWS.
4. Decode the data into a `Message` instance using MsgPack.

## 4. Encrypting and Decrypting

The encrypted form of the data structures are simplified and contain only the
`Message` structure and the sub structures in a standard JWE.

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