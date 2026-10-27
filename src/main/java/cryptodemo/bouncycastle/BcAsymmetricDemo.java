package cryptodemo.bouncycastle;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed25519ctxSigner;
import org.bouncycastle.crypto.signers.Ed25519phSigner;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.crypto.signers.Ed448phSigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.signers.ISO9796d2PSSSigner;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.signers.X931Signer;

/** BouncyCastle lightweight API: RSA, DSA, ECDSA, EdDSA, SM2, Diffie-Hellman, ECDH and XDH. */
public final class BcAsymmetricDemo {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] MSG = "document to be signed".getBytes(StandardCharsets.UTF_8);

    private BcAsymmetricDemo() {
    }

    public static void run() {
        rsa();
        ecdsa();
        dsa();
        eddsa();
        sm2();
        agreement();
    }

    private static void sign(Signer signer, AsymmetricCipherKeyPair kp, String name) throws Exception {
        signer.init(true, kp.getPrivate());
        signer.update(MSG, 0, MSG.length);
        byte[] sig = signer.generateSignature();

        signer.init(false, kp.getPublic());
        signer.update(MSG, 0, MSG.length);
        require(signer.verifySignature(sig), "signature did not verify");

        signer.init(false, kp.getPublic());
        signer.update(MSG, 1, MSG.length - 1);
        require(!signer.verifySignature(sig), "tampered message verified");
        info(name, shortHex(sig));
    }

    private static void rsa() {
        section("RSA");
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(65537), RANDOM, 3072, 100));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        byte[] small = Arrays.copyOf(MSG, 20);
        step("RSA-OAEP (SHA-1)", () -> encrypt(new OAEPEncoding(new RSAEngine()), kp, small));
        step("RSA-OAEP (SHA-256 label digest, SHA-256 MGF1)",
                () -> encrypt(new OAEPEncoding(new RSAEngine(), new SHA256Digest(), new SHA256Digest(), null), kp, small));
        step("RSA PKCS#1 v1.5 encryption (legacy)", () -> encrypt(new PKCS1Encoding(new RSAEngine()), kp, small));

        step("RSA PKCS#1 v1.5 signature (SHA-256)", () -> sign(new RSADigestSigner(new SHA256Digest()), kp, "RSADigestSigner"));
        step("RSA PKCS#1 v1.5 signature (SHA-3 256)", () -> sign(new RSADigestSigner(new SHA3Digest(256)), kp, "RSA-SHA3-256"));
        step("RSA-PSS (SHA-256, salt 32)", () -> sign(new PSSSigner(new RSAEngine(), new SHA256Digest(), 32), kp, "PSSSigner"));
        step("RSA-PSS (SHA-512, salt 64)", () -> sign(new PSSSigner(new RSAEngine(), new SHA512Digest(), 64), kp, "PSSSigner"));
        step("ISO 9796-2 scheme 2 (PSS with message recovery support)",
                () -> sign(new ISO9796d2PSSSigner(new RSAEngine(), new SHA256Digest(), 20), kp, "ISO9796d2PSSSigner"));
        step("ANSI X9.31 signature", () -> sign(new X931Signer(new RSAEngine(), new SHA256Digest()), kp, "X931Signer"));
    }

    private static void encrypt(AsymmetricBlockCipher cipher, AsymmetricCipherKeyPair kp, byte[] data) throws Exception {
        cipher.init(true, kp.getPublic());
        byte[] ct = cipher.processBlock(data, 0, data.length);
        cipher.init(false, kp.getPrivate());
        byte[] pt = cipher.processBlock(ct, 0, ct.length);
        require(Arrays.equals(data, pt), "round trip failed");
        info("ciphertext", shortHex(ct));
    }

    private static ECDomainParameters curve(String name) {
        X9ECParameters x9 = CustomNamedCurves.getByName(name);
        if (x9 == null) {
            x9 = NISTNamedCurves.getByName(name);
        }
        return new ECDomainParameters(x9);
    }

    private static AsymmetricCipherKeyPair ecKeys(ECDomainParameters domain) {
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(domain, RANDOM));
        return gen.generateKeyPair();
    }

    private static void ecdsa() {
        section("ECDSA (raw DSA interface and Signer wrapper)");
        for (String name : new String[] {"secp256r1", "secp384r1", "secp521r1", "secp256k1", "curve25519"}) {
            step("ECDSA " + name, () -> {
                ECDomainParameters domain;
                try {
                    domain = curve(name);
                } catch (RuntimeException e) {
                    throw new IllegalStateException("curve unavailable");
                }
                AsymmetricCipherKeyPair kp = ecKeys(domain);
                sign(new DSADigestSigner(new ECDSASigner(), new SHA256Digest()), kp, "ECDSA/" + name);
            });
        }
        step("ECDSA (r, s) values via the DSA interface", () -> {
            AsymmetricCipherKeyPair kp = ecKeys(curve("secp256r1"));
            byte[] hash = digest(new SHA256Digest(), MSG);
            ECDSASigner signer = new ECDSASigner();
            signer.init(true, new ParametersWithRandom(kp.getPrivate(), RANDOM));
            BigInteger[] rs = signer.generateSignature(hash);
            signer.init(false, kp.getPublic());
            require(signer.verifySignature(hash, rs[0], rs[1]), "verification failed");
            info("r", rs[0].toString(16));
        });
        step("Deterministic ECDSA (RFC 6979 via HMacDSAKCalculator)", () -> {
            AsymmetricCipherKeyPair kp = ecKeys(curve("secp256r1"));
            byte[] hash = digest(new SHA256Digest(), MSG);
            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
            signer.init(true, kp.getPrivate());
            BigInteger[] first = signer.generateSignature(hash);
            signer.init(true, kp.getPrivate());
            BigInteger[] second = signer.generateSignature(hash);
            require(first[0].equals(second[0]) && first[1].equals(second[1]), "signatures differ");
            info("r (identical on both runs)", first[0].toString(16));
        });
    }

    private static byte[] digest(Digest d, byte[] data) {
        d.update(data, 0, data.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    private static void dsa() {
        section("DSA");
        step("DSA 1024-bit (FIPS 186-2 parameter generation, SHA-1)", () -> {
            DSAParametersGenerator pg = new DSAParametersGenerator(new SHA1Digest());
            pg.init(1024, 80, RANDOM);
            DSAParameters params = pg.generateParameters();
            DSAKeyPairGenerator kg = new DSAKeyPairGenerator();
            kg.init(new DSAKeyGenerationParameters(RANDOM, params));
            AsymmetricCipherKeyPair kp = kg.generateKeyPair();
            sign(new DSADigestSigner(new DSASigner(), new SHA1Digest()), kp, "DSA-SHA1");
        });
    }

    private static void eddsa() {
        section("EdDSA (RFC 8032)");
        Ed25519KeyPairGenerator g25519 = new Ed25519KeyPairGenerator();
        g25519.init(new Ed25519KeyGenerationParameters(RANDOM));
        AsymmetricCipherKeyPair ed25519 = g25519.generateKeyPair();
        Ed448KeyPairGenerator g448 = new Ed448KeyPairGenerator();
        g448.init(new Ed448KeyGenerationParameters(RANDOM));
        AsymmetricCipherKeyPair ed448 = g448.generateKeyPair();
        byte[] ctx = "context".getBytes(StandardCharsets.UTF_8);

        step("Ed25519", () -> sign(new Ed25519Signer(), ed25519, "Ed25519"));
        step("Ed25519ctx (context-bound)", () -> sign(new Ed25519ctxSigner(ctx), ed25519, "Ed25519ctx"));
        step("Ed25519ph (pre-hashed)", () -> sign(new Ed25519phSigner(ctx), ed25519, "Ed25519ph"));
        step("Ed448", () -> sign(new Ed448Signer(ctx), ed448, "Ed448"));
        step("Ed448ph (pre-hashed)", () -> sign(new Ed448phSigner(ctx), ed448, "Ed448ph"));
    }

    private static void sm2() {
        section("SM2 (Chinese national standard)");
        ECDomainParameters domain = curve("sm2p256v1");
        step("SM2 signature with user ID", () -> {
            AsymmetricCipherKeyPair kp = ecKeys(domain);
            byte[] id = "1234567812345678".getBytes(StandardCharsets.US_ASCII);
            SM2Signer signer = new SM2Signer(new SM3Digest());
            signer.init(true, new ParametersWithID(new ParametersWithRandom(kp.getPrivate(), RANDOM), id));
            signer.update(MSG, 0, MSG.length);
            byte[] sig = signer.generateSignature();

            signer.init(false, new ParametersWithID(kp.getPublic(), id));
            signer.update(MSG, 0, MSG.length);
            require(signer.verifySignature(sig), "verification failed");
            info("signature", shortHex(sig));
        });
        step("SM2 public-key encryption", () -> {
            AsymmetricCipherKeyPair kp = ecKeys(domain);
            SM2Engine enc = new SM2Engine(new SM3Digest());
            enc.init(true, new ParametersWithRandom(kp.getPublic(), RANDOM));
            byte[] ct = enc.processBlock(MSG, 0, MSG.length);
            SM2Engine dec = new SM2Engine(new SM3Digest());
            dec.init(false, kp.getPrivate());
            require(Arrays.equals(MSG, dec.processBlock(ct, 0, ct.length)), "round trip failed");
            info("ciphertext", shortHex(ct));
        });
    }

    private static void agreement() {
        section("Key agreement");
        step("Finite-field DH (RFC 7919 ffdhe2048)", () -> {
            DHParameters params = DHStandardGroups.rfc7919_ffdhe2048;
            DHBasicKeyPairGenerator gen = new DHBasicKeyPairGenerator();
            gen.init(new DHKeyGenerationParameters(RANDOM, params));
            AsymmetricCipherKeyPair a = gen.generateKeyPair();
            AsymmetricCipherKeyPair b = gen.generateKeyPair();
            DHBasicAgreement agreeA = new DHBasicAgreement();
            agreeA.init(a.getPrivate());
            DHBasicAgreement agreeB = new DHBasicAgreement();
            agreeB.init(b.getPrivate());
            BigInteger sa = agreeA.calculateAgreement((DHPublicKeyParameters) b.getPublic());
            BigInteger sb = agreeB.calculateAgreement((DHPublicKeyParameters) a.getPublic());
            require(sa.equals(sb), "shared secrets differ");
            info("secret bits", sa.bitLength());
            require(((DHPrivateKeyParameters) a.getPrivate()).getX().signum() > 0, "bad private key");
        });
        for (String name : new String[] {"secp256r1", "secp384r1"}) {
            step("ECDH " + name, () -> {
                ECDomainParameters domain = curve(name);
                AsymmetricCipherKeyPair a = ecKeys(domain);
                AsymmetricCipherKeyPair b = ecKeys(domain);
                ECDHBasicAgreement agreeA = new ECDHBasicAgreement();
                agreeA.init(a.getPrivate());
                ECDHBasicAgreement agreeB = new ECDHBasicAgreement();
                agreeB.init(b.getPrivate());
                BigInteger sa = agreeA.calculateAgreement((ECPublicKeyParameters) b.getPublic());
                BigInteger sb = agreeB.calculateAgreement((ECPublicKeyParameters) a.getPublic());
                require(sa.equals(sb), "shared secrets differ");
                info("secret", shortHex(sa.toByteArray()));
            });
        }
        step("ECDH with cofactor (ECDHC)", () -> {
            ECDomainParameters domain = curve("secp256r1");
            AsymmetricCipherKeyPair a = ecKeys(domain);
            AsymmetricCipherKeyPair b = ecKeys(domain);
            ECDHCBasicAgreement agreeA = new ECDHCBasicAgreement();
            agreeA.init(a.getPrivate());
            ECDHCBasicAgreement agreeB = new ECDHCBasicAgreement();
            agreeB.init(b.getPrivate());
            require(agreeA.calculateAgreement((ECPublicKeyParameters) b.getPublic())
                    .equals(agreeB.calculateAgreement((ECPublicKeyParameters) a.getPublic())), "shared secrets differ");
        });
        step("X25519", () -> {
            X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
            gen.init(new X25519KeyGenerationParameters(RANDOM));
            AsymmetricCipherKeyPair a = gen.generateKeyPair();
            AsymmetricCipherKeyPair b = gen.generateKeyPair();
            X25519Agreement agreeA = new X25519Agreement();
            agreeA.init(a.getPrivate());
            X25519Agreement agreeB = new X25519Agreement();
            agreeB.init(b.getPrivate());
            byte[] sa = new byte[agreeA.getAgreementSize()];
            byte[] sb = new byte[agreeB.getAgreementSize()];
            agreeA.calculateAgreement((X25519PublicKeyParameters) b.getPublic(), sa, 0);
            agreeB.calculateAgreement((X25519PublicKeyParameters) a.getPublic(), sb, 0);
            require(Arrays.equals(sa, sb), "shared secrets differ");
            info("secret", shortHex(sa));
        });
        step("X448", () -> {
            X448KeyPairGenerator gen = new X448KeyPairGenerator();
            gen.init(new X448KeyGenerationParameters(RANDOM));
            AsymmetricCipherKeyPair a = gen.generateKeyPair();
            AsymmetricCipherKeyPair b = gen.generateKeyPair();
            X448Agreement agreeA = new X448Agreement();
            agreeA.init(a.getPrivate());
            X448Agreement agreeB = new X448Agreement();
            agreeB.init(b.getPrivate());
            byte[] sa = new byte[agreeA.getAgreementSize()];
            byte[] sb = new byte[agreeB.getAgreementSize()];
            agreeA.calculateAgreement((X448PublicKeyParameters) b.getPublic(), sa, 0);
            agreeB.calculateAgreement((X448PublicKeyParameters) a.getPublic(), sb, 0);
            require(Arrays.equals(sa, sb), "shared secrets differ");
            info("secret", shortHex(sa));
        });
    }
}
