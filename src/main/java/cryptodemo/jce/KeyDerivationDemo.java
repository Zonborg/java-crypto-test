package cryptodemo.jce;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;
import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.PBEKeySpec;

/** Key derivation: PBKDF2 (SecretKeyFactory) and HKDF (javax.crypto.KDF, JDK 25+). */
public final class KeyDerivationDemo {

    private KeyDerivationDemo() {
    }

    public static void run() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        char[] password = "correct horse battery staple".toCharArray();

        section("PBKDF2 via SecretKeyFactory");
        for (String alg : List.of("PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
                "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512")) {
            step(alg, () -> {
                PBEKeySpec spec = new PBEKeySpec(password, salt, 600_000, 256);
                try {
                    SecretKey key = SecretKeyFactory.getInstance(alg).generateSecret(spec);
                    info(alg + " (600k iterations)", shortHex(key.getEncoded()));
                } finally {
                    spec.clearPassword();
                }
            });
        }
        step("Password verification (derive again, constant-time compare)", () -> {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] stored = skf.generateSecret(new PBEKeySpec(password, salt, 100_000, 256)).getEncoded();
            byte[] attempt = skf.generateSecret(new PBEKeySpec(password, salt, 100_000, 256)).getEncoded();
            byte[] wrong = skf.generateSecret(new PBEKeySpec("wrong".toCharArray(), salt, 100_000, 256)).getEncoded();
            require(MessageDigest.isEqual(stored, attempt), "correct password rejected");
            require(!MessageDigest.isEqual(stored, wrong), "wrong password accepted");
        });

        section("Password-based encryption key factories (legacy PBE)");
        for (String alg : List.of("PBEWithMD5AndDES", "PBEWithSHA1AndDESede", "PBEWithSHA1AndRC2_40",
                "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA512AndAES_256")) {
            step(alg, () -> {
                SecretKey key = SecretKeyFactory.getInstance(alg).generateSecret(new PBEKeySpec(password));
                info(alg, key.getAlgorithm() + "/" + key.getFormat());
            });
        }

        section("HKDF via javax.crypto.KDF (RFC 5869)");
        byte[] ikm = new byte[32];
        random.nextBytes(ikm);
        byte[] info = "app v1 encryption".getBytes(StandardCharsets.UTF_8);
        for (String alg : List.of("HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512")) {
            step(alg + " extract-then-expand", () -> {
                KDF kdf = KDF.getInstance(alg);
                byte[] okm = kdf.deriveData(HKDFParameterSpec.ofExtract()
                        .addIKM(ikm).addSalt(salt).thenExpand(info, 42));
                require(okm.length == 42, "wrong OKM length");
                info(kdf.getAlgorithm(), shortHex(okm));
            });
        }
        step("deriveKey(\"AES\", ...) produces a SecretKey", () -> {
            SecretKey key = KDF.getInstance("HKDF-SHA256").deriveKey("AES",
                    HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(salt).thenExpand(info, 32));
            info("algorithm/length", key.getAlgorithm() + "/" + key.getEncoded().length);
        });
        step("Separate extract and expand (PRK reuse)", () -> {
            KDF kdf = KDF.getInstance("HKDF-SHA256");
            SecretKey prk = kdf.deriveKey("PRK", HKDFParameterSpec.ofExtract().addIKM(ikm).addSalt(salt).extractOnly());
            byte[] k1 = kdf.deriveData(HKDFParameterSpec.expandOnly(prk, "enc".getBytes(StandardCharsets.UTF_8), 32));
            byte[] k2 = kdf.deriveData(HKDFParameterSpec.expandOnly(prk, "mac".getBytes(StandardCharsets.UTF_8), 32));
            require(!MessageDigest.isEqual(k1, k2), "contexts produced identical keys");
        });
    }
}
