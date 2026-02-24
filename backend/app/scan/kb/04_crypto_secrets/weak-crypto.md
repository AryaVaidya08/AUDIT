id: weak-crypto
title: Weak or Broken Cryptography (CWE-327)
domain: crypto_secrets
weakness_type: weak_cryptography
cwe: CWE-327
owasp_2021: A02:Cryptographic Failures
exploit_classes: data_exfil,auth_bypass
languages: python,node,java,go,php,ruby
tags: cwe-327,weak-crypto,cryptography,owasp-a02,hashing
severity_guidance: medium
---
Using deprecated or weak cryptographic algorithms provides false security.
MD5 and SHA-1 are broken for integrity purposes; DES/3DES, RC4, and ECB mode are unacceptable for data confidentiality.

Common indicators:
- hashlib.md5() or hashlib.sha1() for password hashing or data integrity
- DES, 3DES, or RC4 ciphers in use for encryption
- AES-ECB mode that leaks patterns in ciphertext
- RSA keys shorter than 2048 bits or DSA/EC keys below recommended sizes

Impact:
- password hash cracking via precomputed rainbow tables
- ciphertext decryption by adversaries with moderate resources
- data integrity bypass through collision attacks

Recommended remediation:
- use bcrypt, scrypt, or Argon2 for password hashing
- use AES-GCM or ChaCha20-Poly1305 for symmetric encryption
- enforce minimum key sizes and modern TLS cipher suites
