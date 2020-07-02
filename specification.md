# CSM v1.0 specification

## 1.0 Certificate File Contents

All v1.0 CSM certificate files must start with `---csm-cert-1---`.

Then in no particular order the certificate must contain a public key and may contain optional certificate flags and other certificate data.

Public keys must be in the format `pub:(algorithm):(number of lines encoded key occupies):(base64 encoded public key)`.

Certificate flags (if included) must be in the format `flags:(flag1):(flag2)...`.

Other certificate data (if included) must be in the format `(name):(data)`.

Then in the order specified in this specification the certificate must contain its signed hash, and the public key of the signer.

The signed hash must be in the format `hash:(hashing algorithm):(number of lines signature occupies):(base64 encoded signature)`.

The signer's public key must be in the format `signer:(algorithm):(number of lines encoded key occupies):(base64 encoded public key)`.

If the certificate does not have a signer (CA, etc...), then it must be signed by the private key associated with its public key.

The certificate must end with `--end-csm-cert---`.

### 1.1 Certificate File Flags

All flags listed in this section must be supported (or ignored if they do not apply to the use case), other custom flags may be used by implementations however they are not recommended.

#### 1.1.1 Implied Certificate File Flags

Unless otherwise overridden these flags are implied, their definitions are explained in #1.1.2.

`NoCA`
`Sign`
`Encrypt`
`Auth`
`NoVerified`

#### 1.1.2 Certificate File Flags

Note: Some software may require certain extra data in certificates for different applications/flags, this is left up to the developer to handle as this specification does not require any extra data for most flags.

`CA` - Specifies that this certificate's key may act as a certificate authority and sign certificates.

`NoCA` - An implied flag that specifies that this certificate's key cannot sign certificates.

`Sign` - An implied flag that specifies that this certificate's key may sign data.

`NoSign` - Specifies that this certificate's key may not sign data.

`Encrypt` - An implied flag that specifies that this certificate's key may encrypt data.

`NoEncrypt` - Specifies that this certificate's key may not encrypt data.

`Auth` - An implied flag that specifies that this certificate's key may be used for authentication.

`NoAuth` - Specifies that this certificate's key may not be used for authentication.

`Verified` - Specifies that the CA's in the certificate chain have verified that this key belongs to an ip address/domain, this flag requires that `hosts` be set in the other certificate data to the ip address(s) and/or domain name(s) of the host separated by commas.

`NoVerified` - An implied flag that specifies that this certificate is not verified to belong to an ip address/domain.

## 2.0 Certificate Chain File Contents

All v1.0 CSM certificate chains must start with `---csm-cert-chain---`.

The certificate chain file must then contain all of the certificates exactly as specified in #1.0 in the order that they are signed in (ex: first certificate is the certificate at the end of the chain, then its signer, then its signer, etc...).

The certificate chain file must end with `---end-csm-cert-chain---`.

## 3.0 Key File Contents

All v1.0 CSM key files must start with `---csm-key-1---` or `---csm-enc-key-1---`.

`---csm-key-1---` is for plaintext keys, and `---csm-enc-key-1---` is for encrypted keys.

All keys must end with `---end-csm-key---` after it's contents.

### 3.1 Plaintext Key File Contents

All v1.0 plaintext CSM key files must contain a public key and a private key in any order.

The public key must be in the format `pub:(algorithm):(number of lines encoded key occupies):(base64 encoded public key)`.

The private key must be in the format `priv:(algorithm):(number of lines encoded key occupies):(base64 encoded private key)`

### 3.2 Encrypted Key File Contents

All v1.0 encrypted CSM key files must contain a public key and a encrypted private key in any order.

The public key must be in the format `pub:(algorithm):(number of lines encoded key occupies):(base64 encoded public key)`.

The private key must be in the format `priv:(encryption algorithm):(key algorithm):(number of lines encrypted key occupies):(encrypted private key encoded in base64)`.