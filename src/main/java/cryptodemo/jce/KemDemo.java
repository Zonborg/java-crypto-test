package cryptodemo.jce;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

/** javax.crypto.KEM: ML-KEM (FIPS 203, JDK 24+) and DHKEM (RFC 9180). */
public final class KemDemo {

    private KemDemo() {
    }

    public static void run() {
        section("ML-KEM");
        for (String alg : new String[] {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
            step(alg, () -> {
                KeyPair kp = KeyPairGenerator.getInstance(alg).generateKeyPair();
                KEM kem = KEM.getInstance("ML-KEM");

                KEM.Encapsulated sent = kem.newEncapsulator(kp.getPublic()).encapsulate();
                SecretKey received = kem.newDecapsulator(kp.getPrivate()).decapsulate(sent.encapsulation());

                require(Arrays.equals(sent.key().getEncoded(), received.getEncoded()), "shared secrets differ");
                info("ciphertext", sent.encapsulation().length + " bytes");
                info("shared secret", shortHex(received.getEncoded()));
            });
        }
        step("encapsulate(from, to, algorithm) derives a key slice", () -> {
            KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
            KEM kem = KEM.getInstance("ML-KEM-768");
            KEM.Encapsulated enc = kem.newEncapsulator(kp.getPublic()).encapsulate(0, 16, "AES");
            SecretKey key = kem.newDecapsulator(kp.getPrivate()).decapsulate(enc.encapsulation(), 0, 16, "AES");
            require(Arrays.equals(enc.key().getEncoded(), key.getEncoded()), "derived keys differ");
            info("AES key", key.getEncoded().length + " bytes");
        });
        step("Encapsulator / Decapsulator size accessors", () -> {
            KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
            KEM kem = KEM.getInstance("ML-KEM-768");
            KEM.Encapsulator e = kem.newEncapsulator(kp.getPublic());
            KEM.Decapsulator d = kem.newDecapsulator(kp.getPrivate());
            info("secretSize", e.secretSize() + " / " + d.secretSize());
            info("encapsulationSize", e.encapsulationSize() + " / " + d.encapsulationSize());
        });

        section("DHKEM (RFC 9180)");
        step("DHKEM with X25519", () -> {
            KeyPair kp = KeyPairGenerator.getInstance("X25519").generateKeyPair();
            KEM kem = KEM.getInstance("DHKEM");
            KEM.Encapsulated sent = kem.newEncapsulator(kp.getPublic()).encapsulate();
            SecretKey received = kem.newDecapsulator(kp.getPrivate()).decapsulate(sent.encapsulation());
            require(Arrays.equals(sent.key().getEncoded(), received.getEncoded()), "shared secrets differ");
            info("shared secret", shortHex(received.getEncoded()));
        });
        step("DHKEM with EC P-256", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            KEM kem = KEM.getInstance("DHKEM");
            KEM.Encapsulated sent = kem.newEncapsulator(kp.getPublic()).encapsulate();
            SecretKey received = kem.newDecapsulator(kp.getPrivate()).decapsulate(sent.encapsulation());
            require(Arrays.equals(sent.key().getEncoded(), received.getEncoded()), "shared secrets differ");
        });
    }
}
