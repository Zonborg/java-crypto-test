package cryptodemo.jce;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.step;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/** javax.crypto.CipherInputStream, CipherOutputStream and SealedObject. */
public final class CipherStreamDemo {

    private record Account(String owner, long balance) implements Serializable {
    }

    private CipherStreamDemo() {
    }

    public static void run() {
        section("Cipher streams");
        byte[] data = new byte[100_000];
        new SecureRandom().nextBytes(data);

        step("CipherOutputStream / CipherInputStream (AES/CBC)", () -> {
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);

            Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            try (CipherOutputStream out = new CipherOutputStream(sink, enc)) {
                out.write(data);
            }

            Cipher dec = Cipher.getInstance("AES/CBC/PKCS5Padding");
            dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            try (CipherInputStream in = new CipherInputStream(new ByteArrayInputStream(sink.toByteArray()), dec)) {
                require(Arrays.equals(data, in.readAllBytes()), "stream round trip failed");
            }
            info("ciphertext", sink.size() + " bytes");
        });
        step("Streaming AES-GCM (tag verified when the stream is closed/finished)", () -> {
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);

            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
            enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            try (CipherOutputStream out = new CipherOutputStream(sink, enc)) {
                out.write(data);
            }

            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
            dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            try (CipherInputStream in = new CipherInputStream(new ByteArrayInputStream(sink.toByteArray()), dec)) {
                require(Arrays.equals(data, in.readAllBytes()), "stream round trip failed");
            }
        });

        section("SealedObject");
        step("Seal and unseal a Serializable object with AES/GCM", () -> {
            SecretKey key = KeyGenerator.getInstance("AES").generateKey();
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
            enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));

            SealedObject sealed = new SealedObject(new Account("alice", 1_000L), enc);
            info("algorithm", sealed.getAlgorithm());

            Account opened = (Account) sealed.getObject(key);
            require(opened.equals(new Account("alice", 1_000L)), "unsealed object differs");
            info("unsealed", opened);
        });
    }
}
