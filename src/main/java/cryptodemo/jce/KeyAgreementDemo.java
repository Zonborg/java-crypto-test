package cryptodemo.jce;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import javax.crypto.KDF;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** javax.crypto.KeyAgreement: DH, ECDH, X25519 and X448. */
public final class KeyAgreementDemo {

    private KeyAgreementDemo() {
    }

    public static void run() {
        section("Finite-field Diffie-Hellman");
        step("DH-2048", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
            kpg.initialize(2048);
            agree("DH", kpg.generateKeyPair(), kpg.generateKeyPair(), "DH");
        });

        section("Elliptic-curve Diffie-Hellman");
        for (String curve : new String[] {"secp256r1", "secp384r1", "secp521r1"}) {
            step("ECDH " + curve, () -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec(curve));
                agree("ECDH", kpg.generateKeyPair(), kpg.generateKeyPair(), "ECDH " + curve);
            });
        }

        section("XDH (RFC 7748)");
        step("X25519", () -> agree("X25519", KeyPairGenerator.getInstance("X25519").generateKeyPair(),
                KeyPairGenerator.getInstance("X25519").generateKeyPair(), "X25519"));
        step("X448", () -> agree("X448", KeyPairGenerator.getInstance("X448").generateKeyPair(),
                KeyPairGenerator.getInstance("X448").generateKeyPair(), "X448"));
        step("XDH (algorithm-agnostic)", () -> agree("XDH", KeyPairGenerator.getInstance("X25519").generateKeyPair(),
                KeyPairGenerator.getInstance("X25519").generateKeyPair(), "XDH"));

        section("Deriving a symmetric key");
        step("generateSecret(byte[], int) writes into a caller buffer", () -> {
            KeyPair alice = KeyPairGenerator.getInstance("X25519").generateKeyPair();
            KeyPair bob = KeyPairGenerator.getInstance("X25519").generateKeyPair();
            KeyAgreement a = KeyAgreement.getInstance("X25519");
            a.init(alice.getPrivate());
            a.doPhase(bob.getPublic(), true);
            byte[] buffer = new byte[32];
            info("bytes written", a.generateSecret(buffer, 0));
        });
        step("Derive an AES key from the shared secret with HKDF-SHA256", () -> {
            KeyPair alice = KeyPairGenerator.getInstance("X25519").generateKeyPair();
            KeyPair bob = KeyPairGenerator.getInstance("X25519").generateKeyPair();
            KeyAgreement a = KeyAgreement.getInstance("X25519");
            a.init(alice.getPrivate());
            a.doPhase(bob.getPublic(), true);
            SecretKey shared = a.generateSecret("Generic");
            SecretKey aes = KDF.getInstance("HKDF-SHA256").deriveKey("AES", HKDFParameterSpec.ofExtract()
                    .addIKM(shared).thenExpand("key-agreement demo".getBytes(StandardCharsets.UTF_8), 32));
            info("derived AES key", shortHex(aes.getEncoded()));
        });
        step("Hash the raw shared secret into an AES key (never use it directly)", () -> {
            KeyPair alice = KeyPairGenerator.getInstance("X25519").generateKeyPair();
            KeyPair bob = KeyPairGenerator.getInstance("X25519").generateKeyPair();
            KeyAgreement a = KeyAgreement.getInstance("X25519");
            a.init(alice.getPrivate());
            a.doPhase(bob.getPublic(), true);
            byte[] shared = a.generateSecret();
            SecretKey key = new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(shared), "AES");
            info("derived key", shortHex(key.getEncoded()));
        });
    }

    private static void agree(String algorithm, KeyPair alice, KeyPair bob, String label) throws Exception {
        KeyAgreement a = KeyAgreement.getInstance(algorithm);
        a.init(alice.getPrivate());
        a.doPhase(bob.getPublic(), true);
        byte[] secretA = a.generateSecret();

        KeyAgreement b = KeyAgreement.getInstance(algorithm);
        b.init(bob.getPrivate());
        b.doPhase(alice.getPublic(), true);
        byte[] secretB = b.generateSecret();

        require(Arrays.equals(secretA, secretB), "shared secrets differ");
        info(label + " [" + a.getProvider().getName() + "]", shortHex(secretA));
    }
}
