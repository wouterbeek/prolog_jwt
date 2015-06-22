**plJwt**
=========

A library bringing JSON Web Token (JWT) support
to [SWI-Prolog](http://www.swi-prolog.org).

**JSON Web Token (JWT)** is a compact claims representation format
intended for space constrained environments such as HTTP
Authorization headers and URI query parameters.
[RFC 7519](https://tools.ietf.org/html/rfc7519)

Content is secured and signed by using a **JSON Web Signature (JWS)**.
[RFC 7515](https://tools.ietf.org/html/rfc7515)

Cryptographic key can be specified a **JSON Web Key (JWK)**
or as a **JWK Set**.
[RFC 7517](https://tools.ietf.org/html/rfc7517)

Cryptographic algorithms and identifiers are drawn from
the **JSON Web Algorithms (JWA)** collection.
[RFC 7518](https://tools.ietf.org/html/rfc7518)

This is version 0.1.0, created by [Wouter Beek](http://www.wouterbeek.com)
in June 2015.

This library is licensed under the Lesser General Public License Vers. 3,
June 2007, see LICENSE.txt.



Install
=======

Other than having a normal SWI-Prolog install, the only installation step is to clone this repository from [Github](https://github.com/wouterbeek/plJwt) or install through [SWI-Prolog's built-in packaging system](http://www.swi-prolog.org/pack/list):

```prolog
?- pack_install(plJwt).
```



Usage
=====

Encoding usage
--------------

```prolog
?- use_module(library(jwt/jwt_enc)).
?- jwt_enc(json{alg: "HS256", typ: "JWT"}, json{data: "data"}, json{k: "secret", kty: "oct"}, Token).
Token = 'eyJhbGciOiJIUzI1NiIsICJ0eXAiOiJKV1QifQ.eyJkYXRhIjoiZGF0YSJ9.LOyFMl4_ntjclIDodouH50lRBSLhohtLwHuNBmWTxjI'.
```

Decoding usage
--------------

```prolog
?- use_module(library(jwt/jwt_dec)).
?- jwt_dec($Token, json{k: "secret", kty: "oct"}, Payload).
Payload = _G8726{data:"data"}.
```


Encoding API
============

```prolog
jwt_enc(+Header:dict, +Payload:dict, ?Key, -Token:atom) is det.
```

The JSON Object Signing and Encryption (JOSE) `Header` is
a SWI7 dictionary for which the following claims are supported:

  * **Algorithm (`alg`)**
    Supported values:
    * `"HS256"` for HMAC using SHA-256.
    * `"HS384"` for HMAC using SHA-384.
    * `"HS512"` for HMAC using SHA-512.
    * `"none"` for no digital signature or MAC performed.

  * **Content type (`cty`)**
    Declares the media type of the secured content (the payload).

  * **Critical (`crit`)**
    Indicates that extensions to this specification and/or JWA are being used
    that MUST be understood and processed.
    The value is an array listing the critical Header Parameter names.

  * **JSON Web Key (`jwk`)**
    The public key that is used to digitally sign the JWS.

  * **Key ID (`kid`)**
    A hint indicating which key was used to secure the JWS.
    When used with a JWK, the `kid` value is used to match a JWK `kid` value.

  * **Type (`typ`)**
    Declares the media type of the complete JWS.
    It is recommended to omit the `application/` prefix if no further
    forward slash appears in the media type.
    The following values are supported:
    * `JOSE` indicates that this is a JWS or JWE using the
      JWS Compact Serialization or the JWE Compact Serialization.
    * `JOSE+JSON` indicates that this is a JWS or JWE using the
      JWS JSON Serialization or the JWE JSON Serialization.
    * `JWT` indicates that this is a JWT.

`Payload` is a SWI7 dictionary that contains arbitrary JSON data
but where the following claim names have a reserved meaning:

  * **Audience (`aud`)**
    Identifies the recipients that the JWT is intended for.
    If present this should be `"SWI-Prolog"` or
    should be a list containing `"SWI-Prolog"`.
    This value is checked by Prolog as part of JWT decription.
  
  * **Issuer (`iss`)**
    Identifies the principal that issued the JWT.
    This value is set by Prolog as part of the JWT encription.
  
  * **Subject (`sub`)**
    Identifies the principal that is the subject of the JWT.
    The claims in a JWT are normally statements about the subject.

  * **Expiration Time (`exp`)**
    Identifies the expiration time on or after which the JWT MUST NOT
    be accepted for processing.
    This value is checked by Prolog as part of JWT decription.

  * **Issued at (`iat`)**
    Identifies the time at which the JWT was issued.
    This claim can be used to determine the age of the JWT.
    This value is set by Prolog as part of the JWT encription.

  * **JWT ID (`jti`)**
    Unique identifier for the JWT.

  * **Not before (`nbf`)**
    Identifies the time before which the JWT MUST NOT be accepted for
    processing.
    This value is checked by Prolog as part of JWT decription.

The JSON Web Key (JWK) `Key` is either of the following:

  * Uninstantiated, in case
    * the JOSE `Header`'s `alg` parameter is set to `"none"`, or
    * the JOSE `Header`'s parameter `jwk` specifies a public key.

  * A JWK Set of private keys, in case the JOSE `Header`'s `kid` parameter
    specifies a specific JWK.

  * A JWK of a private key, in case the JOSE `Header` contains
    no information about keys.

A JWT Set is a SWI7 dictionary for which the following claim is supported:

  * **Keys (`keys`)
    An array of JWKs.

A JSON Web Key (JWK) is a SWI7 dictionary for which
the following claims are supported:

  * **Algorithm (`alg`)**
    The algorithm intended for use with the key.
    Supported values: `"HS256"`, `"HS384"`, `"HS512"`, `"none"`.
  
  * **Key ID (`kid`)**
    Used to match a specific key, e.g., to choose among a set of keys within
    a JWK Set during key rollover.
  
  * **Key Operations (`key_ops`)**
    Identifies the operation(s) for which the key is intended to be used.
    Its value is an array of key operation values.
    Supported values:
    *  `"sign"` to compute a digital signature or MAC.
    *  `"verify"` to verify a digital signature or MAC.
    *  `"encrypt"` to encrypt content.
    *  `"decrypt"` to decrypt content and validate decryption, if applicable.
    *  `"wrapKey"` to encrypt key.
    *  `"unwrapKey"` to decrypt key and validate decryption, if applicable.
    *  `"deriveKey"` to derive key.
    *  `"deriveBits"` to derive bits not to be used as a key.

  * **Key Type (`kty`)** [Required]
    Identifies the cryptographic algorithm family used with the key.
    Supported values:
      * `"oct"` for octet sequence (used to represent symmetric keys).
    
  * **Key Value (`k`)**
    The value of the symmetric (or other single-valued) key.
    Represented as the base64url encoding of the octet sequence containing
    the key value.
  
  * **Public key use (`use`)**
    Identifies the intended use of the public key: data encryption (`"enc"`)
    or signature verification (`"sig"`).
    Supported values: `"enc"`, `"sig"`.



Run tests
=========

Test for this library are run in the following way:

```bash
$ swipl test/jwt_test.pl
?- jwt_test(X).
```
