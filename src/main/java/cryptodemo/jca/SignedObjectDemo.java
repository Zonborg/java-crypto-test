package cryptodemo.jca;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.step;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignedObject;

/** java.security.SignedObject. */
public final class SignedObjectDemo {

    private record Account(String owner, long balance) implements Serializable {
    }

    private SignedObjectDemo() {
    }

    public static void run() {
        section("SignedObject");
        step("Sign and verify a Serializable object (SHA256withRSA)", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            SignedObject signed = new SignedObject(new Account("bob", 250L), kp.getPrivate(),
                    Signature.getInstance("SHA256withRSA"));
            require(signed.verify(kp.getPublic(), Signature.getInstance("SHA256withRSA")), "verification failed");
            info("signature algorithm", signed.getAlgorithm());
            info("payload", signed.getObject());
        });
        step("SignedObject with a non-matching key fails verification", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair signer = kpg.generateKeyPair();
            KeyPair other = kpg.generateKeyPair();
            SignedObject signed = new SignedObject("payload".getBytes(StandardCharsets.UTF_8), signer.getPrivate(),
                    Signature.getInstance("SHA256withECDSA"));
            require(!signed.verify(other.getPublic(), Signature.getInstance("SHA256withECDSA")),
                    "verified with wrong key");
        });
    }
}
