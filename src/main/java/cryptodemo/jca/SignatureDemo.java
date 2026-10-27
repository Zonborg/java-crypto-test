package cryptodemo.jca;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EdDSAParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/** java.security.Signature: RSA, RSASSA-PSS, ECDSA, DSA, EdDSA and ML-DSA. */
public final class SignatureDemo {

    private static final byte[] MSG = "document to be signed".getBytes(StandardCharsets.UTF_8);

    private SignatureDemo() {
    }

    public static void run() {
        section("RSA (PKCS#1 v1.5)");
        KeyPair rsa = generate("RSA", 3072, null);
        for (String alg : new String[] {"SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA512/256withRSA",
                "SHA3-256withRSA", "SHA3-512withRSA", "SHA224withRSA", "SHA1withRSA", "MD5withRSA", "MD2withRSA"}) {
            step(alg, () -> signAndVerify(alg, rsa, null));
        }

        section("RSASSA-PSS");
        step("RSASSA-PSS SHA-256 / MGF1-SHA-256 / salt 32", () -> signAndVerify("RSASSA-PSS", rsa,
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, PSSParameterSpec.TRAILER_FIELD_BC)));
        step("RSASSA-PSS SHA-384 / MGF1-SHA-384 / salt 48", () -> signAndVerify("RSASSA-PSS", rsa,
                new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, PSSParameterSpec.TRAILER_FIELD_BC)));
        step("RSASSA-PSS SHA-512 / MGF1-SHA-512 / salt 64", () -> signAndVerify("RSASSA-PSS", rsa,
                new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, PSSParameterSpec.TRAILER_FIELD_BC)));
        step("Key restricted to RSASSA-PSS key type", () -> {
            KeyPair pss = generate("RSASSA-PSS", 2048, null);
            signAndVerify("RSASSA-PSS", pss,
                    new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        });

        section("ECDSA");
        KeyPair p256 = generate("EC", 0, new ECGenParameterSpec("secp256r1"));
        KeyPair p384 = generate("EC", 0, new ECGenParameterSpec("secp384r1"));
        KeyPair p521 = generate("EC", 0, new ECGenParameterSpec("secp521r1"));
        step("SHA256withECDSA (P-256, DER-encoded signature)", () -> signAndVerify("SHA256withECDSA", p256, null));
        step("SHA384withECDSA (P-384)", () -> signAndVerify("SHA384withECDSA", p384, null));
        step("SHA512withECDSA (P-521)", () -> signAndVerify("SHA512withECDSA", p521, null));
        step("SHA3-256withECDSA", () -> signAndVerify("SHA3-256withECDSA", p256, null));
        step("SHA256withECDSAinP1363Format (raw r||s, as used by JWS)", () -> signAndVerify("SHA256withECDSAinP1363Format", p256, null));
        step("SHA384withECDSAinP1363Format", () -> signAndVerify("SHA384withECDSAinP1363Format", p384, null));
        step("SHA512withECDSAinP1363Format", () -> signAndVerify("SHA512withECDSAinP1363Format", p521, null));
        step("NONEwithECDSA (caller supplies a 32-byte digest)", () -> {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(MSG);
            Signature signer = Signature.getInstance("NONEwithECDSA");
            signer.initSign(p256.getPrivate());
            signer.update(digest);
            byte[] sig = signer.sign();
            Signature verifier = Signature.getInstance("NONEwithECDSA");
            verifier.initVerify(p256.getPublic());
            verifier.update(digest);
            require(verifier.verify(sig), "verification failed");
        });

        section("DSA");
        KeyPair dsa = generate("DSA", 2048, null);
        step("SHA256withDSA", () -> signAndVerify("SHA256withDSA", dsa, null));
        step("SHA384withDSA", () -> signAndVerify("SHA384withDSA", dsa, null));
        step("SHA256withDSAinP1363Format", () -> signAndVerify("SHA256withDSAinP1363Format", dsa, null));
        step("SHA1withDSA (legacy)", () -> signAndVerify("SHA1withDSA", generate("DSA", 1024, null), null));

        section("EdDSA");
        step("Ed25519", () -> signAndVerify("Ed25519", generate("Ed25519", 0, null), null));
        step("Ed448", () -> signAndVerify("Ed448", generate("Ed448", 0, null), null));
        step("EdDSA (algorithm-agnostic, key decides)", () -> signAndVerify("EdDSA", generate("Ed25519", 0, null), null));
        step("Ed25519ph prehash via EdDSAParameterSpec", () -> signAndVerify("Ed25519",
                generate("Ed25519", 0, null), new EdDSAParameterSpec(true)));
        step("Ed25519ctx-style context via EdDSAParameterSpec(false, context)", () -> signAndVerify("EdDSA",
                generate("Ed25519", 0, null), new EdDSAParameterSpec(false, "ctx".getBytes(StandardCharsets.UTF_8))));

        section("ML-DSA (FIPS 204, JDK 24+)");
        for (String alg : new String[] {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}) {
            step(alg, () -> {
                KeyPair kp = KeyPairGenerator.getInstance(alg).generateKeyPair();
                byte[] sig = signAndVerify(alg, kp, null);
                info("signature size", sig.length + " bytes");
            });
        }
        step("ML-DSA (algorithm-agnostic) with ML-DSA-65 key", () ->
                signAndVerify("ML-DSA", KeyPairGenerator.getInstance("ML-DSA-65").generateKeyPair(), null));

        section("API surface");
        step("Multi-part update() / sign(byte[],int,int)", () -> {
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(p256.getPrivate());
            signer.update(MSG[0]);
            signer.update(MSG, 1, MSG.length - 1);
            byte[] out = new byte[200];
            int n = signer.sign(out, 0, out.length);
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(p256.getPublic());
            verifier.update(MSG);
            require(verifier.verify(out, 0, n), "verification failed");
        });
        step("Tampered message is rejected (verify returns false)", () -> {
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(p256.getPrivate());
            signer.update(MSG);
            byte[] sig = signer.sign();
            byte[] tampered = MSG.clone();
            tampered[0] ^= 1;
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(p256.getPublic());
            verifier.update(tampered);
            require(!verifier.verify(sig), "tampered message verified");
        });
        step("Wrong public key is rejected", () -> {
            KeyPair other = generate("EC", 0, new ECGenParameterSpec("secp256r1"));
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(p256.getPrivate());
            signer.update(MSG);
            byte[] sig = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(other.getPublic());
            verifier.update(MSG);
            require(!verifier.verify(sig), "signature verified under the wrong key");
        });
        step("getAlgorithm / getProvider / getParameters", () -> {
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            info("algorithm", s.getAlgorithm());
            info("provider", s.getProvider().getName());
            info("parameters", s.getParameters());
        });
    }

    private static KeyPair generate(String alg, int keySize, AlgorithmParameterSpec spec) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
            if (spec != null) {
                kpg.initialize(spec);
            } else if (keySize > 0) {
                kpg.initialize(keySize);
            }
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("cannot generate " + alg + " key", e);
        }
    }

    private static byte[] signAndVerify(String algorithm, KeyPair kp, AlgorithmParameterSpec params) throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        if (params != null) {
            signer.setParameter(params);
        }
        signer.initSign(kp.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance(algorithm);
        if (params != null) {
            verifier.setParameter(params);
        }
        verifier.initVerify(kp.getPublic());
        verifier.update(MSG);
        require(verifier.verify(sig), "signature did not verify");
        info(algorithm + " [" + signer.getProvider().getName() + "]", shortHex(sig));
        return sig;
    }
}
