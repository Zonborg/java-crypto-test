package cryptodemo.jce;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** javax.crypto.Mac: HMAC algorithms and password-based MACs. */
public final class MacDemo {

    private static final byte[] MSG = "message to authenticate".getBytes(StandardCharsets.UTF_8);

    private MacDemo() {
    }

    public static void run() {
        section("HMAC algorithms (KeyGenerator-produced keys)");
        List<String> algorithms = List.of(
                "HmacMD5", "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512",
                "HmacSHA512/224", "HmacSHA512/256", "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384", "HmacSHA3-512");
        for (String alg : algorithms) {
            step(alg, () -> {
                SecretKey key = KeyGenerator.getInstance(alg).generateKey();
                Mac mac = Mac.getInstance(alg);
                mac.init(key);
                byte[] tag = mac.doFinal(MSG);
                info(alg + " [" + mac.getProvider().getName() + ", " + mac.getMacLength() + " bytes]", shortHex(tag));
            });
        }

        section("API surface");
        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        SecretKey key = new SecretKeySpec(keyBytes, "HmacSHA256");

        step("update(byte) / update(byte[],int,int) / update(ByteBuffer) / doFinal()", () -> {
            Mac oneShot = Mac.getInstance("HmacSHA256");
            oneShot.init(key);
            byte[] expected = oneShot.doFinal(MSG);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            mac.update(MSG[0]);
            mac.update(MSG, 1, 4);
            mac.update(ByteBuffer.wrap(MSG, 5, MSG.length - 5));
            require(MessageDigest.isEqual(expected, mac.doFinal()), "incremental MAC mismatch");
        });

        step("doFinal(byte[], int) into caller buffer", () -> {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            mac.update(MSG);
            byte[] out = new byte[mac.getMacLength()];
            mac.doFinal(out, 0);
        });

        step("reset() and re-use after doFinal", () -> {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            byte[] first = mac.doFinal(MSG);
            mac.update("noise".getBytes(StandardCharsets.UTF_8));
            mac.reset();
            require(MessageDigest.isEqual(first, mac.doFinal(MSG)), "reset failed");
        });

        step("clone()", () -> {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            mac.update(MSG, 0, 5);
            Mac copy = (Mac) mac.clone();
            mac.update(MSG, 5, MSG.length - 5);
            copy.update(MSG, 5, MSG.length - 5);
            require(MessageDigest.isEqual(mac.doFinal(), copy.doFinal()), "clone diverged");
        });

        step("Verify tag with constant-time compare; tampering detected", () -> {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            byte[] tag = mac.doFinal(MSG);

            mac.init(key);
            require(MessageDigest.isEqual(tag, mac.doFinal(MSG)), "valid tag rejected");
            mac.init(key);
            byte[] tampered = MSG.clone();
            tampered[0] ^= 1;
            require(!MessageDigest.isEqual(tag, mac.doFinal(tampered)), "tampered message accepted");
        });

        section("Password-based MACs");
        for (String alg : List.of("PBEWithHmacSHA1", "PBEWithHmacSHA256", "PBEWithHmacSHA512")) {
            step(alg, () -> {
                SecretKey pbeKey = new SecretKeySpec("correct horse".getBytes(StandardCharsets.UTF_8), alg);
                byte[] salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                Mac mac = Mac.getInstance(alg);
                mac.init(pbeKey, new PBEParameterSpec(salt, 10_000));
                info(alg, shortHex(mac.doFinal(MSG)));
            });
        }
    }
}
