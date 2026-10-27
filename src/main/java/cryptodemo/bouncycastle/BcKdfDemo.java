package cryptodemo.bouncycastle;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.generators.KDF1BytesGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.generators.MGF1BytesGenerator;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.ISO18033KDFParameters;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.MGFParameters;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.crypto.prng.X931SecureRandomBuilder;

/** BouncyCastle lightweight API: key derivation, password hashing and deterministic random bit generators. */
public final class BcKdfDemo {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] PASSWORD = "correct horse battery staple".toCharArray();

    private BcKdfDemo() {
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    public static void run() {
        passwordHashing();
        passwordBasedKeyDerivation();
        keyDerivationFunctions();
        drbgs();
    }

    private static void passwordHashing() {
        section("Memory-hard password hashing");
        byte[] salt = random(16);
        byte[] pw = new String(PASSWORD).getBytes(StandardCharsets.UTF_8);

        step("scrypt (N=2^15, r=8, p=1)", () -> {
            byte[] key = SCrypt.generate(pw, salt, 1 << 15, 8, 1, 32);
            info("derived key", shortHex(key));
        });
        for (int type : new int[] {Argon2Parameters.ARGON2_d, Argon2Parameters.ARGON2_i, Argon2Parameters.ARGON2_id}) {
            String name = type == Argon2Parameters.ARGON2_d ? "Argon2d"
                    : type == Argon2Parameters.ARGON2_i ? "Argon2i" : "Argon2id";
            step(name + " (64 MiB, 3 iterations, 2 lanes)", () -> {
                Argon2Parameters params = new Argon2Parameters.Builder(type)
                        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                        .withSalt(salt).withIterations(3).withMemoryAsKB(64 * 1024).withParallelism(2).build();
                Argon2BytesGenerator gen = new Argon2BytesGenerator();
                gen.init(params);
                byte[] out = new byte[32];
                gen.generateBytes(PASSWORD, out);
                info(name, shortHex(out));
            });
        }
        step("bcrypt crypt-string format: generate and check", () -> {
            String hash = OpenBSDBCrypt.generate(PASSWORD, salt, 12);
            require(OpenBSDBCrypt.checkPassword(hash, PASSWORD), "correct password rejected");
            require(!OpenBSDBCrypt.checkPassword(hash, "wrong".toCharArray()), "wrong password accepted");
            info("hash", hash);
        });
    }

    private static void passwordBasedKeyDerivation() {
        section("Password-based key derivation (PBKDF)");
        byte[] salt = random(16);
        byte[] pw = PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(PASSWORD);

        step("PBKDF2-HMAC-SHA1 / SHA256 / SHA512", () -> {
            org.bouncycastle.crypto.Digest[] digests = {new SHA1Digest(), new SHA256Digest(), new SHA512Digest()};
            for (org.bouncycastle.crypto.Digest d : digests) {
                PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(d);
                gen.init(pw, salt, 100_000);
                KeyParameter key = (KeyParameter) gen.generateDerivedParameters(256);
                info("PBKDF2-" + d.getAlgorithmName(), shortHex(key.getKey()));
            }
        });
        step("PKCS#12 key derivation (PKCS12ParametersGenerator)", () -> {
            PKCS12ParametersGenerator gen = new PKCS12ParametersGenerator(new SHA256Digest());
            gen.init(PBEParametersGenerator.PKCS12PasswordToBytes(PASSWORD), salt, 10_000);
            KeyParameter key = (KeyParameter) gen.generateDerivedParameters(256);
            info("derived key", shortHex(key.getKey()));
        });
        step("OpenSSL EVP_BytesToKey (legacy)", () -> {
            OpenSSLPBEParametersGenerator gen = new OpenSSLPBEParametersGenerator();
            gen.init(PBEParametersGenerator.PKCS5PasswordToBytes(PASSWORD), Arrays.copyOf(salt, 8));
            KeyParameter key = (KeyParameter) gen.generateDerivedParameters(256);
            info("derived key", shortHex(key.getKey()));
        });
    }

    private static void keyDerivationFunctions() {
        section("Key derivation functions (from a high-entropy secret)");
        byte[] ikm = random(32);
        byte[] salt = random(16);
        byte[] ctx = "app v1".getBytes(StandardCharsets.UTF_8);

        step("HKDF (RFC 5869) with SHA-256", () -> {
            HKDFBytesGenerator gen = new HKDFBytesGenerator(new SHA256Digest());
            gen.init(new HKDFParameters(ikm, salt, ctx));
            byte[] okm = new byte[42];
            gen.generateBytes(okm, 0, okm.length);
            info("okm", shortHex(okm));
        });
        step("HKDF expand-only (skip extract)", () -> {
            HKDFBytesGenerator gen = new HKDFBytesGenerator(new SHA256Digest());
            gen.init(HKDFParameters.skipExtractParameters(ikm, ctx));
            byte[] okm = new byte[32];
            gen.generateBytes(okm, 0, okm.length);
            info("okm", shortHex(okm));
        });
        step("KDF1 (ISO 18033)", () -> {
            KDF1BytesGenerator gen = new KDF1BytesGenerator(new SHA256Digest());
            gen.init(new ISO18033KDFParameters(ikm));
            byte[] out = new byte[32];
            gen.generateBytes(out, 0, out.length);
            info("output", shortHex(out));
        });
        step("KDF2 (ISO 18033 / ANSI X9.63)", () -> {
            KDF2BytesGenerator gen = new KDF2BytesGenerator(new SHA256Digest());
            gen.init(new ISO18033KDFParameters(ikm));
            byte[] out = new byte[48];
            gen.generateBytes(out, 0, out.length);
            info("output", shortHex(out));
        });
        step("MGF1 mask generation", () -> {
            MGF1BytesGenerator gen = new MGF1BytesGenerator(new SHA256Digest());
            gen.init(new MGFParameters(ikm));
            byte[] out = new byte[64];
            gen.generateBytes(out, 0, out.length);
            info("mask", shortHex(out));
        });
        step("SP 800-108 counter-mode KDF (HMAC-SHA256)", () -> {
            KDFCounterBytesGenerator gen = new KDFCounterBytesGenerator(new HMac(new SHA256Digest()));
            gen.init(new KDFCounterParameters(ikm, null, ctx, 16));
            byte[] out = new byte[32];
            gen.generateBytes(out, 0, out.length);
            info("output", shortHex(out));
        });
    }

    private static void drbgs() {
        section("Deterministic random bit generators (NIST SP 800-90A / ANSI X9.31)");
        byte[] nonce = random(16);
        byte[] personalization = "java-crypto-test".getBytes(StandardCharsets.UTF_8);

        step("Hash_DRBG (SHA-512)", () -> {
            SecureRandom drbg = new SP800SecureRandomBuilder(RANDOM, true)
                    .setPersonalizationString(personalization).buildHash(new SHA512Digest(), nonce, false);
            byte[] out = new byte[32];
            drbg.nextBytes(out);
            info("output", shortHex(out));
        });
        step("HMAC_DRBG (SHA-256)", () -> {
            SecureRandom drbg = new SP800SecureRandomBuilder(RANDOM, true)
                    .setPersonalizationString(personalization).buildHMAC(new HMac(new SHA256Digest()), nonce, false);
            byte[] out = new byte[32];
            drbg.nextBytes(out);
            info("output", shortHex(out));
        });
        step("CTR_DRBG (AES-256)", () -> {
            SecureRandom drbg = new SP800SecureRandomBuilder(RANDOM, true)
                    .setPersonalizationString(personalization).buildCTR(AESEngine.newInstance(), 256, nonce, false);
            byte[] out = new byte[32];
            drbg.nextBytes(out);
            info("output", shortHex(out));
        });
        step("ANSI X9.31 PRNG (AES)", () -> {
            SecureRandom prng = new X931SecureRandomBuilder(RANDOM, true)
                    .build(AESEngine.newInstance(), new KeyParameter(random(16)), false);
            byte[] out = new byte[32];
            prng.nextBytes(out);
            info("output", shortHex(out));
        });
    }
}
