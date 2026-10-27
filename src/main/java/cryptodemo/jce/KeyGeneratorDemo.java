package cryptodemo.jce;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.step;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/** javax.crypto.KeyGenerator, SecretKeyFactory and SecretKey specs. */
public final class KeyGeneratorDemo {

    private KeyGeneratorDemo() {
    }

    public static void run() {
        section("KeyGenerator");
        for (int bits : new int[] {128, 192, 256}) {
            step("AES-" + bits, () -> {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(bits, new SecureRandom());
                SecretKey key = kg.generateKey();
                require(key.getEncoded().length * 8 == bits, "wrong key size");
                info("format/algorithm", key.getFormat() + "/" + key.getAlgorithm());
            });
        }
        for (String alg : List.of("DES", "DESede", "Blowfish", "RC2", "ARCFOUR", "ChaCha20",
                "HmacSHA1", "HmacSHA256", "HmacSHA384", "HmacSHA512", "HmacSHA3-256")) {
            step(alg, () -> {
                KeyGenerator kg = KeyGenerator.getInstance(alg);
                SecretKey key = kg.generateKey();
                info(alg + " [" + kg.getProvider().getName() + "]", key.getEncoded().length * 8 + " bits");
            });
        }

        section("SecretKeySpec");
        step("Wrap raw bytes as an AES key", () -> {
            byte[] raw = new byte[32];
            new SecureRandom().nextBytes(raw);
            SecretKey key = new SecretKeySpec(raw, "AES");
            require(Arrays.equals(raw, key.getEncoded()), "encoding mismatch");
            require(key.equals(new SecretKeySpec(raw, 0, 32, "AES")), "equals failed");
        });

        section("SecretKeyFactory");
        step("DES: DESKeySpec round trip + weak key check", () -> {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
            byte[] raw = KeyGenerator.getInstance("DES").generateKey().getEncoded();
            DESKeySpec spec = new DESKeySpec(raw);
            SecretKey key = skf.generateSecret(spec);
            require(!DESKeySpec.isWeak(raw, 0), "weak key");
            require(((DESKeySpec) skf.getKeySpec(key, DESKeySpec.class)).getKey().length == 8, "spec mismatch");
        });
        step("DESede: DESedeKeySpec round trip", () -> {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede");
            byte[] raw = KeyGenerator.getInstance("DESede").generateKey().getEncoded();
            SecretKey key = skf.generateSecret(new DESedeKeySpec(raw));
            require(((DESedeKeySpec) skf.getKeySpec(key, DESedeKeySpec.class)).getKey().length == 24, "spec mismatch");
        });
        step("translateKey (import key from another provider)", () -> {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("DESede");
            SecretKey foreign = new SecretKeySpec(KeyGenerator.getInstance("DESede").generateKey().getEncoded(), "DESede");
            SecretKey translated = skf.translateKey(foreign);
            info("translated class", translated.getClass().getSimpleName());
        });
        step("PBEKeySpec: password, salt, iterations, key length; clearPassword()", () -> {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), salt, 1000, 256);
            info("iterations/keyLength", spec.getIterationCount() + "/" + spec.getKeyLength());
            spec.clearPassword();
            try {
                spec.getPassword();
                throw new IllegalStateException("password should be cleared");
            } catch (IllegalStateException expected) {
                info("after clearPassword", "getPassword() throws " + expected.getClass().getSimpleName());
            }
        });
        step("Key interface: getAlgorithm / getFormat / getEncoded / isDestroyed", () -> {
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            info("algorithm", key.getAlgorithm());
            info("format", key.getFormat());
            info("isDestroyed", key.isDestroyed());
        });
    }
}
