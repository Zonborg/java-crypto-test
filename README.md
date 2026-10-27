# Java Cryptography Showcase (JCA / JCE / BouncyCastle)

A console application that exercises the cryptographic APIs of the Java Cryptography Architecture (JCA, `java.security.*`), the Java Cryptography Extension (JCE, `javax.crypto.*`) and the BouncyCastle library. The JCA and JCE demos use only the JDK; the BouncyCastle demos need the BouncyCastle jars.

## Prerequisites

- JDK 25 or later (uses `javax.crypto.KDF` for HKDF and ML-KEM / ML-DSA, which need JDK 24+)
- BouncyCastle 1.86 jars (`bcprov`, `bcpkix`, `bcutil`, `bcpg`, all `-jdk18on`), resolved automatically by Maven or downloaded into `lib/` as shown below
- Maven is optional

## Running

With Maven:

```bash
mvn compile exec:java
```

Without Maven (PowerShell), download the jars once into `lib/` (git-ignored), then compile and run:

```powershell
New-Item -ItemType Directory lib -Force | Out-Null
$ProgressPreference = 'SilentlyContinue'
foreach ($a in 'bcprov','bcpkix','bcutil','bcpg') {
  Invoke-WebRequest "https://repo1.maven.org/maven2/org/bouncycastle/$a-jdk18on/1.86/$a-jdk18on-1.86.jar" -OutFile "lib/$a-jdk18on-1.86.jar"
}
javac --release 25 -cp "lib/*" -d out (Get-ChildItem src -Recurse -Filter *.java).FullName
java -cp "out;lib/*" cryptodemo.Main
```

On Linux or macOS use `:` instead of `;` in the classpath.

Pass names to run a subset (case-insensitive substring match): `cryptodemo.Main jca` runs every JCA demo, `cryptodemo.Main "BC "` runs every BouncyCastle demo, and `cryptodemo.Main "BC PKIX" jce:` combines filters.

Each operation prints `[OK]`, `[FAIL]` or `[SKIP]`. A failure does not stop the run, which makes the output useful for checking what a given JDK or provider configuration supports. A summary is printed at the end.

## Layout

Shared files live in `src/main/java/cryptodemo/`: `Main.java`, `DemoSupport.java` and `TestCredentials.java` (generates throwaway RSA and EC key pairs with the JDK `keytool` at runtime).

### JCA: `cryptodemo/jca/` (`java.security.*`)

| File | Classes covered |
|---|---|
| `ProviderDemo.java` | `Provider`, `Security`, `Provider.Service`, runtime provider registration, crypto policy |
| `MessageDigestDemo.java` | `MessageDigest`, `DigestInputStream`, `DigestOutputStream` |
| `SecureRandomDemo.java` | `SecureRandom`, `DrbgParameters`, `RandomGenerator` |
| `AlgorithmParametersDemo.java` | `AlgorithmParameters`, `AlgorithmParameterGenerator` |
| `KeyPairDemo.java` | `KeyPairGenerator`, `KeyFactory`, X.509 / PKCS#8 key specs |
| `SignatureDemo.java` | `Signature`, `PSSParameterSpec`, `EdDSAParameterSpec` |
| `SignedObjectDemo.java` | `SignedObject` |
| `KeyStoreDemo.java` | `KeyStore` and its entry / protection / builder types |
| `CertificateDemo.java` | `CertificateFactory`, `X509Certificate`, `CertPath`, `CertPathValidator`, `CertPathBuilder`, `CertStore` |

### JCE: `cryptodemo/jce/` (`javax.crypto.*`)

| File | Classes covered |
|---|---|
| `CipherDemo.java` | `Cipher`, `GCMParameterSpec`, `IvParameterSpec`, `ChaCha20ParameterSpec`, `OAEPParameterSpec`, `PBEParameterSpec`, wrap/unwrap |
| `CipherStreamDemo.java` | `CipherInputStream`, `CipherOutputStream`, `SealedObject` |
| `MacDemo.java` | `Mac` |
| `KeyGeneratorDemo.java` | `KeyGenerator`, `SecretKeyFactory`, `SecretKeySpec`, `DESKeySpec`, `DESedeKeySpec`, `PBEKeySpec` |
| `KeyDerivationDemo.java` | PBKDF2, legacy PBE key factories, `KDF` (HKDF) |
| `KeyAgreementDemo.java` | `KeyAgreement` |
| `KemDemo.java` | `KEM` |

### BouncyCastle: `cryptodemo/bouncycastle/`

| File | Area |
|---|---|
| `BcDigestMacDemo.java` | Lightweight API: digests, XOFs (SHAKE, cSHAKE, ParallelHash, TupleHash, Blake3), HMAC, CMAC, GMAC, KMAC, Poly1305, SipHash |
| `BcSymmetricDemo.java` | Lightweight API: block ciphers, modes, padding, stream ciphers, AEAD (GCM, CCM, EAX, OCB, GCM-SIV, ChaCha20-Poly1305, Ascon and other NIST LWC), key wrap, format-preserving encryption |
| `BcAsymmetricDemo.java` | Lightweight API: RSA, DSA, ECDSA, EdDSA, SM2, DH, ECDH, X25519, X448 |
| `BcKdfDemo.java` | Lightweight API: scrypt, Argon2, bcrypt, PBKDF2, HKDF, KDF1/2, MGF1, SP 800-108, Hash/HMAC/CTR DRBG, X9.31 |
| `BcProviderDemo.java` | The `BC` JCA/JCE provider: digests, MACs, ciphers, PBE, signatures, key agreement, ECIES, SM2 |
| `BcPostQuantumDemo.java` | ML-KEM, FrodoKEM, NTRU, NTRU Prime, HQC, Classic McEliece, ML-DSA, SLH-DSA, Falcon, XMSS, LMS |
| `BcPkixDemo.java` | bcpkix: X.509 chains, CSR, CRL, OCSP, CMS (signed, enveloped, auth-enveloped), PEM / PKCS#8, BCFKS / BKS / UBER keystores |
| `BcPgpDemo.java` | bcpg: OpenPGP key rings, public-key and passphrase encryption, signatures, ASCII armor |

## Algorithms Demonstrated

### Hashing and MACs
- MD2, MD5, SHA-1, SHA-224/256/384/512, SHA-512/224, SHA-512/256, SHA3-224/256/384/512
- HmacMD5, HmacSHA1/224/256/384/512, HmacSHA512/224, HmacSHA512/256, HmacSHA3-*
- Password-based MACs (`PBEWithHmacSHA*`)

### Randomness and key derivation
- `SecureRandom`: default, strong, DRBG (with `DrbgParameters`), SHA1PRNG, NativePRNG*, Windows-PRNG
- PBKDF2WithHmacSHA1/224/256/384/512
- Legacy PBE: PBEWithMD5AndDES, PBEWithSHA1AndDESede, PBEWithSHA1AndRC2_40, PBEWithHmacSHA*AndAES_*
- HKDF-SHA256/384/512 (extract, expand, extract-then-expand)

### Symmetric encryption
- AES: ECB, CBC, CTR, CFB, CFB8, OFB, CTS, PCBC, GCM; KW, KWP and AESWrap key wrapping
- ChaCha20 and ChaCha20-Poly1305
- Legacy: DES, DESede (3DES), Blowfish, RC2, ARCFOUR
- PBES2: `PBEWithHmacSHA256AndAES_128/256`, `PBEWithHmacSHA512AndAES_256`

### Asymmetric encryption, signatures and key agreement
- RSA: PKCS#1 v1.5, OAEP (SHA-1/256/512), raw, hybrid RSA-OAEP + AES-GCM
- Signatures: RSA PKCS#1 (SHA-1 to SHA-3), RSASSA-PSS, ECDSA (DER and P1363, P-256/384/521), DSA, Ed25519, Ed448, ML-DSA-44/65/87
- Key agreement: DH, ECDH, X25519, X448
- KEM: ML-KEM-512/768/1024, DHKEM (X25519, P-256)

### Keys, stores and certificates
- Key generation for RSA, RSASSA-PSS, DSA, DH, EC, EdDSA, XDH, ML-DSA, ML-KEM; encode/decode via `KeyFactory`
- KeyStores: PKCS12, JKS, JCEKS, cacerts, Windows-MY / Windows-ROOT (Windows only)
- X.509 parsing, extensions, PKIX path validation and building

### BouncyCastle highlights
- Digests beyond the JDK: Whirlpool, RIPEMD-128/160/256/320, Tiger, GOST R 34.11, SM3, DSTU 7564, Blake2b/2s, Blake3, Skein, Keccak, SHAKE-based functions
- Ciphers beyond the JDK: Twofish, Serpent, Camellia, ARIA, SM4, SEED, CAST5/6, IDEA, RC5/RC6, Noekeon, GOST 28147, XSalsa20, Salsa20, HC-128/256, Grain, ZUC, VMPC, AES-GCM-SIV, OCB, EAX, Ascon, Xoodyak
- Password hashing: scrypt, Argon2d/i/id, bcrypt
- Asymmetric: SM2, ECGOST3410-2012, DSTU 4145, ElGamal, ECIES, brainpool and secp256k1 curves
- Post-quantum: ML-KEM, FrodoKEM, NTRU, NTRU Prime, HQC, Classic McEliece, ML-DSA, SLH-DSA, Falcon, XMSS, LMS
- Formats and protocols: X.509 v3 (including ML-DSA, SLH-DSA, Falcon and EdDSA certificates), PKCS#10, CRL, OCSP, CMS, PEM, PKCS#8 (PBES2), OpenPGP

## Notes

- Several algorithms (MD2, MD5, SHA-1, DES, RC2, ARCFOUR, RSA PKCS#1 v1.5 encryption, ECB, JKS) are included to show that the API supports them. They are not recommended for new designs.
- `TestCredentials` runs `keytool` from the running JDK to create self-signed certificates in a temporary directory that is deleted immediately after loading, so no key material is stored in the repository.
- Platform-specific entries (`NativePRNG*`, `Windows-PRNG`, `Windows-MY`, `Windows-ROOT`) print `[SKIP]` when unavailable.
- TLS/JSSE (`SSLContext`, `KeyManagerFactory`, `TrustManagerFactory`) is outside JCA/JCE and not covered.
- BouncyCastle 1.86 moved ML-KEM, ML-DSA, SLH-DSA, FrodoKEM, Classic McEliece and the LMS/XMSS parameter classes from `org.bouncycastle.pqc.crypto.*` into `org.bouncycastle.crypto.*`; the post-quantum demo uses the 1.86 locations. BIKE now lives under `org.bouncycastle.pqc.legacy` and is not demonstrated.
- Timestamping (TSP) and CMS compressed / authenticated data are not covered.
