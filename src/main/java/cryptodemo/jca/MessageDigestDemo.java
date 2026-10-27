package cryptodemo.jca;

import static cryptodemo.DemoSupport.hex;
import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.List;

/** java.security.MessageDigest: hashing algorithms and API surface. */
public final class MessageDigestDemo {

    private static final byte[] MSG = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);

    private MessageDigestDemo() {
    }

    public static void run() {
        section("Algorithms");
        List<String> algorithms = List.of(
                "MD2", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
                "SHA-512/224", "SHA-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512");
        for (String alg : algorithms) {
            step(alg, () -> {
                MessageDigest md = MessageDigest.getInstance(alg);
                byte[] digest = md.digest(MSG);
                info(md.getAlgorithm() + " [" + md.getProvider().getName() + ", " + md.getDigestLength() + " bytes]",
                        shortHex(digest));
            });
        }

        section("API surface");
        step("update(byte) / update(byte[]) / update(byte[],int,int) / update(ByteBuffer)", () -> {
            MessageDigest oneShot = MessageDigest.getInstance("SHA-256");
            byte[] expected = oneShot.digest(MSG);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(MSG[0]);
            md.update(MSG, 1, 9);
            md.update(ByteBuffer.wrap(MSG, 10, 10));
            md.update(java.util.Arrays.copyOfRange(MSG, 20, MSG.length));
            require(MessageDigest.isEqual(expected, md.digest()), "incremental digest mismatch");
        });

        step("digest(byte[], int, int) into caller buffer", () -> {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(MSG);
            byte[] out = new byte[md.getDigestLength()];
            int n = md.digest(out, 0, out.length);
            require(n == 32, "unexpected length " + n);
        });

        step("reset()", () -> {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("garbage".getBytes(StandardCharsets.UTF_8));
            md.reset();
            require(MessageDigest.isEqual(md.digest(MSG), MessageDigest.getInstance("SHA-256").digest(MSG)),
                    "reset did not clear state");
        });

        step("clone() mid-stream", () -> {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(MSG, 0, 10);
            MessageDigest copy = (MessageDigest) md.clone();
            md.update(MSG, 10, MSG.length - 10);
            copy.update(MSG, 10, MSG.length - 10);
            require(MessageDigest.isEqual(md.digest(), copy.digest()), "clone diverged");
        });

        step("MessageDigest.isEqual (constant time)", () -> {
            byte[] a = MessageDigest.getInstance("SHA-256").digest(MSG);
            byte[] b = a.clone();
            b[0] ^= 1;
            require(MessageDigest.isEqual(a, a.clone()), "equal arrays reported different");
            require(!MessageDigest.isEqual(a, b), "different arrays reported equal");
        });

        step("getInstance(alg, provider)", () -> {
            MessageDigest md = MessageDigest.getInstance("SHA-256", "SUN");
            info("provider", md.getProvider());
        });

        step("toString / getAlgorithm / getDigestLength", () -> {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            info("algorithm", md.getAlgorithm());
            info("length", md.getDigestLength());
            info("toString", md);
        });

        section("Streams");
        step("DigestInputStream", () -> {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (DigestInputStream in = new DigestInputStream(new ByteArrayInputStream(MSG), md)) {
                in.readAllBytes();
            }
            info("digest", hex(md.digest()));
        });

        step("DigestOutputStream", () -> {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (DigestOutputStream out = new DigestOutputStream(new ByteArrayOutputStream(), md)) {
                out.write(MSG);
            }
            info("digest", hex(md.digest()));
        });
    }
}
