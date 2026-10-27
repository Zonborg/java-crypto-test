package cryptodemo.jce;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.RC2ParameterSpec;

/** javax.crypto.Cipher: symmetric, AEAD, password-based, asymmetric and key wrapping. */
public final class CipherDemo {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] PLAINTEXT =
            "Sensitive data that needs protecting - 0123456789".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AAD = "header-v1".getBytes(StandardCharsets.UTF_8);

    private CipherDemo() {
    }

    public static void run() {
        aesModes();
        aead();
        streamCiphers();
        legacyBlockCiphers();
        passwordBased();
        rsa();
        keyWrapping();
        apiSurface();
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static SecretKey key(String alg, int bits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(alg);
        kg.init(bits);
        return kg.generateKey();
    }

    /** Encrypts then decrypts with an IV-based transformation and verifies the round trip. */
    private static void ivRoundTrip(String transformation, SecretKey key, int ivLength) throws Exception {
        byte[] iv = random(ivLength);
        Cipher enc = Cipher.getInstance(transformation);
        enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ct = enc.doFinal(PLAINTEXT);

        Cipher dec = Cipher.getInstance(transformation);
        dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        require(Arrays.equals(PLAINTEXT, dec.doFinal(ct)), "round trip failed");
        info(transformation + " [" + enc.getProvider().getName() + "]", shortHex(ct));
    }

    private static void aesModes() {
        section("AES modes");
        SecretKey aes = null;
        try {
            aes = key("AES", 256);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        final SecretKey aesKey = aes;

        step("AES/ECB/PKCS5Padding (insecure: no IV, leaks patterns)", () -> {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] ct = c.doFinal(PLAINTEXT);
            c.init(Cipher.DECRYPT_MODE, aesKey);
            require(Arrays.equals(PLAINTEXT, c.doFinal(ct)), "round trip failed");
            info("ciphertext", shortHex(ct));
        });
        step("AES/CBC/PKCS5Padding", () -> ivRoundTrip("AES/CBC/PKCS5Padding", aesKey, 16));
        step("AES/CBC/NoPadding (block-aligned input)", () -> {
            byte[] aligned = Arrays.copyOf(PLAINTEXT, 48);
            byte[] iv = random(16);
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] ct = c.doFinal(aligned);
            c.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            require(Arrays.equals(aligned, c.doFinal(ct)), "round trip failed");
        });
        step("AES/CBC/ISO10126Padding", () -> ivRoundTrip("AES/CBC/ISO10126Padding", aesKey, 16));
        step("AES/CTR/NoPadding", () -> ivRoundTrip("AES/CTR/NoPadding", aesKey, 16));
        step("AES/CFB/NoPadding", () -> ivRoundTrip("AES/CFB/NoPadding", aesKey, 16));
        step("AES/CFB8/NoPadding", () -> ivRoundTrip("AES/CFB8/NoPadding", aesKey, 16));
        step("AES/OFB/NoPadding", () -> ivRoundTrip("AES/OFB/NoPadding", aesKey, 16));
        step("AES/CTS/NoPadding (ciphertext stealing)", () -> ivRoundTrip("AES/CTS/NoPadding", aesKey, 16));
        step("AES/PCBC/PKCS5Padding", () -> ivRoundTrip("AES/PCBC/PKCS5Padding", aesKey, 16));
        step("Let provider choose the IV (getIV / getParameters)", () -> {
            Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            enc.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] ct = enc.doFinal(PLAINTEXT);
            Cipher dec = Cipher.getInstance("AES/CBC/PKCS5Padding");
            dec.init(Cipher.DECRYPT_MODE, aesKey, enc.getParameters());
            require(Arrays.equals(PLAINTEXT, dec.doFinal(ct)), "round trip failed");
            info("generated IV", shortHex(enc.getIV()));
        });
    }

    private static void aead() {
        section("Authenticated encryption (AEAD)");
        step("AES/GCM/NoPadding with AAD", () -> {
            SecretKey key = key("AES", 256);
            byte[] iv = random(12);
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
            enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            enc.updateAAD(AAD);
            byte[] ct = enc.doFinal(PLAINTEXT);

            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
            dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            dec.updateAAD(AAD);
            require(Arrays.equals(PLAINTEXT, dec.doFinal(ct)), "round trip failed");
            info("ciphertext+tag", shortHex(ct));
        });
        step("AES/GCM tamper detection (AEADBadTagException)", () -> {
            SecretKey key = key("AES", 128);
            byte[] iv = random(12);
            Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
            enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] ct = enc.doFinal(PLAINTEXT);
            ct[0] ^= 1;
            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
            dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            try {
                dec.doFinal(ct);
                throw new IllegalStateException("tampering was not detected");
            } catch (AEADBadTagException expected) {
                info("result", "rejected as expected");
            }
        });
        step("AES_256/GCM/NoPadding (key-size-specific transformation)", () -> {
            SecretKey key = key("AES", 256);
            byte[] iv = random(12);
            Cipher c = Cipher.getInstance("AES_256/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] ct = c.doFinal(PLAINTEXT);
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            require(Arrays.equals(PLAINTEXT, c.doFinal(ct)), "round trip failed");
        });
        step("ChaCha20-Poly1305", () -> {
            SecretKey key = key("ChaCha20", 256);
            byte[] nonce = random(12);
            Cipher enc = Cipher.getInstance("ChaCha20-Poly1305");
            enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
            enc.updateAAD(AAD);
            byte[] ct = enc.doFinal(PLAINTEXT);

            Cipher dec = Cipher.getInstance("ChaCha20-Poly1305");
            dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
            dec.updateAAD(AAD);
            require(Arrays.equals(PLAINTEXT, dec.doFinal(ct)), "round trip failed");
            info("ciphertext+tag", shortHex(ct));
        });
    }

    private static void streamCiphers() {
        section("Stream ciphers");
        step("ChaCha20 (unauthenticated) with ChaCha20ParameterSpec", () -> {
            SecretKey key = key("ChaCha20", 256);
            byte[] nonce = random(12);
            Cipher enc = Cipher.getInstance("ChaCha20");
            enc.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 1));
            byte[] ct = enc.doFinal(PLAINTEXT);
            Cipher dec = Cipher.getInstance("ChaCha20");
            dec.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 1));
            require(Arrays.equals(PLAINTEXT, dec.doFinal(ct)), "round trip failed");
            info("ciphertext", shortHex(ct));
        });
        step("ARCFOUR / RC4 (legacy, broken)", () -> {
            SecretKey key = key("ARCFOUR", 128);
            Cipher enc = Cipher.getInstance("ARCFOUR");
            enc.init(Cipher.ENCRYPT_MODE, key);
            byte[] ct = enc.doFinal(PLAINTEXT);
            Cipher dec = Cipher.getInstance("ARCFOUR");
            dec.init(Cipher.DECRYPT_MODE, key);
            require(Arrays.equals(PLAINTEXT, dec.doFinal(ct)), "round trip failed");
        });
    }

    private static void legacyBlockCiphers() {
        section("Other block ciphers (legacy)");
        step("DESede/CBC/PKCS5Padding (3DES)", () -> ivRoundTrip("DESede/CBC/PKCS5Padding", key("DESede", 168), 8));
        step("DES/CBC/PKCS5Padding (broken)", () -> ivRoundTrip("DES/CBC/PKCS5Padding", key("DES", 56), 8));
        step("Blowfish/CBC/PKCS5Padding", () -> ivRoundTrip("Blowfish/CBC/PKCS5Padding", key("Blowfish", 128), 8));
        step("RC2/CBC/PKCS5Padding with RC2ParameterSpec", () -> {
            SecretKey key = key("RC2", 128);
            byte[] iv = random(8);
            Cipher enc = Cipher.getInstance("RC2/CBC/PKCS5Padding");
            enc.init(Cipher.ENCRYPT_MODE, key, new RC2ParameterSpec(128, iv));
            byte[] ct = enc.doFinal(PLAINTEXT);
            Cipher dec = Cipher.getInstance("RC2/CBC/PKCS5Padding");
            dec.init(Cipher.DECRYPT_MODE, key, new RC2ParameterSpec(128, iv));
            require(Arrays.equals(PLAINTEXT, dec.doFinal(ct)), "round trip failed");
        });
    }

    private static void passwordBased() {
        section("Password-based encryption (PBE)");
        char[] password = "s3cret-passphrase".toCharArray();
        for (String alg : new String[] {"PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256",
                "PBEWithHmacSHA512AndAES_256"}) {
            step(alg, () -> {
                byte[] salt = random(16);
                SecretKey key = SecretKeyFactory.getInstance(alg).generateSecret(new PBEKeySpec(password));
                PBEParameterSpec params = new PBEParameterSpec(salt, 100_000, new IvParameterSpec(random(16)));
                Cipher enc = Cipher.getInstance(alg);
                enc.init(Cipher.ENCRYPT_MODE, key, params);
                byte[] ct = enc.doFinal(PLAINTEXT);
                Cipher dec = Cipher.getInstance(alg);
                dec.init(Cipher.DECRYPT_MODE, key, params);
                require(Arrays.equals(PLAINTEXT, dec.doFinal(ct)), "round trip failed");
                info(alg, shortHex(ct));
            });
        }
        for (String alg : new String[] {"PBEWithMD5AndDES", "PBEWithSHA1AndDESede", "PBEWithSHA1AndRC2_40"}) {
            step(alg + " (legacy)", () -> {
                SecretKey key = SecretKeyFactory.getInstance(alg).generateSecret(new PBEKeySpec(password));
                PBEParameterSpec params = new PBEParameterSpec(random(8), 10_000);
                Cipher enc = Cipher.getInstance(alg);
                enc.init(Cipher.ENCRYPT_MODE, key, params);
                byte[] ct = enc.doFinal(PLAINTEXT);
                Cipher dec = Cipher.getInstance(alg);
                dec.init(Cipher.DECRYPT_MODE, key, params);
                require(Arrays.equals(PLAINTEXT, dec.doFinal(ct)), "round trip failed");
            });
        }
    }

    private static void rsa() {
        section("Asymmetric encryption (RSA)");
        KeyPair kp;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(3072);
            kp = kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        final KeyPair rsaKeys = kp;
        byte[] small = Arrays.copyOf(PLAINTEXT, 32);

        step("RSA/ECB/PKCS1Padding (legacy, padding-oracle prone)", () -> {
            Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            enc.init(Cipher.ENCRYPT_MODE, rsaKeys.getPublic());
            byte[] ct = enc.doFinal(small);
            Cipher dec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dec.init(Cipher.DECRYPT_MODE, rsaKeys.getPrivate());
            require(Arrays.equals(small, dec.doFinal(ct)), "round trip failed");
        });
        step("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", () -> {
            Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            enc.init(Cipher.ENCRYPT_MODE, rsaKeys.getPublic());
            byte[] ct = enc.doFinal(small);
            Cipher dec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            dec.init(Cipher.DECRYPT_MODE, rsaKeys.getPrivate());
            require(Arrays.equals(small, dec.doFinal(ct)), "round trip failed");
        });
        step("RSA-OAEP SHA-256 / MGF1-SHA-256 via OAEPParameterSpec", () -> {
            OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            Cipher enc = Cipher.getInstance("RSA/ECB/OAEPPadding");
            enc.init(Cipher.ENCRYPT_MODE, rsaKeys.getPublic(), oaep);
            byte[] ct = enc.doFinal(small);
            Cipher dec = Cipher.getInstance("RSA/ECB/OAEPPadding");
            dec.init(Cipher.DECRYPT_MODE, rsaKeys.getPrivate(), oaep);
            require(Arrays.equals(small, dec.doFinal(ct)), "round trip failed");
            info("ciphertext", shortHex(ct));
        });
        step("RSA-OAEP with named transformation SHA-512", () -> {
            Cipher enc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
            enc.init(Cipher.ENCRYPT_MODE, rsaKeys.getPublic());
            byte[] ct = enc.doFinal(small);
            Cipher dec = Cipher.getInstance("RSA/ECB/OAEPWithSHA-512AndMGF1Padding");
            dec.init(Cipher.DECRYPT_MODE, rsaKeys.getPrivate());
            require(Arrays.equals(small, dec.doFinal(ct)), "round trip failed");
        });
        step("RSA/ECB/NoPadding (raw, textbook RSA)", () -> {
            byte[] block = new byte[384];
            block[383] = 42;
            Cipher enc = Cipher.getInstance("RSA/ECB/NoPadding");
            enc.init(Cipher.ENCRYPT_MODE, rsaKeys.getPublic());
            byte[] ct = enc.doFinal(block);
            Cipher dec = Cipher.getInstance("RSA/ECB/NoPadding");
            dec.init(Cipher.DECRYPT_MODE, rsaKeys.getPrivate());
            require(Arrays.equals(block, dec.doFinal(ct)), "round trip failed");
        });
        step("Hybrid encryption: RSA-OAEP wraps an AES-GCM key", () -> {
            SecretKey dek = key("AES", 256);
            OAEPParameterSpec oaep = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT);
            Cipher wrap = Cipher.getInstance("RSA/ECB/OAEPPadding");
            wrap.init(Cipher.WRAP_MODE, rsaKeys.getPublic(), oaep);
            byte[] wrappedDek = wrap.wrap(dek);

            byte[] iv = random(12);
            Cipher data = Cipher.getInstance("AES/GCM/NoPadding");
            data.init(Cipher.ENCRYPT_MODE, dek, new GCMParameterSpec(128, iv));
            byte[] ct = data.doFinal(PLAINTEXT);

            Cipher unwrap = Cipher.getInstance("RSA/ECB/OAEPPadding");
            unwrap.init(Cipher.UNWRAP_MODE, rsaKeys.getPrivate(), oaep);
            Key recovered = unwrap.unwrap(wrappedDek, "AES", Cipher.SECRET_KEY);
            Cipher dec = Cipher.getInstance("AES/GCM/NoPadding");
            dec.init(Cipher.DECRYPT_MODE, recovered, new GCMParameterSpec(128, iv));
            require(Arrays.equals(PLAINTEXT, dec.doFinal(ct)), "round trip failed");
        });
    }

    private static void keyWrapping() {
        section("Key wrapping");
        step("AESWrap (RFC 3394 key wrap)", () -> {
            SecretKey kek = key("AES", 256);
            SecretKey cek = key("AES", 128);
            Cipher c = Cipher.getInstance("AESWrap");
            c.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = c.wrap(cek);
            c.init(Cipher.UNWRAP_MODE, kek);
            Key out = c.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            require(Arrays.equals(cek.getEncoded(), out.getEncoded()), "unwrap mismatch");
            info("wrapped", shortHex(wrapped));
        });
        step("AES/KW/NoPadding", () -> {
            SecretKey kek = key("AES", 256);
            SecretKey cek = key("AES", 256);
            Cipher c = Cipher.getInstance("AES/KW/NoPadding");
            c.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = c.wrap(cek);
            c.init(Cipher.UNWRAP_MODE, kek);
            require(Arrays.equals(cek.getEncoded(), c.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded()),
                    "unwrap mismatch");
        });
        step("AES/KWP/NoPadding (RFC 5649, arbitrary length)", () -> {
            SecretKey kek = key("AES", 256);
            SecretKey cek = new javax.crypto.spec.SecretKeySpec(random(20), "HmacSHA1");
            Cipher c = Cipher.getInstance("AES/KWP/NoPadding");
            c.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = c.wrap(cek);
            c.init(Cipher.UNWRAP_MODE, kek);
            require(Arrays.equals(cek.getEncoded(), c.unwrap(wrapped, "HmacSHA1", Cipher.SECRET_KEY).getEncoded()),
                    "unwrap mismatch");
        });
        step("DESedeWrap", () -> {
            SecretKey kek = key("DESede", 168);
            SecretKey cek = key("DESede", 168);
            Cipher c = Cipher.getInstance("DESedeWrap");
            c.init(Cipher.WRAP_MODE, kek);
            byte[] wrapped = c.wrap(cek);
            c.init(Cipher.UNWRAP_MODE, kek);
            require(Arrays.equals(cek.getEncoded(), c.unwrap(wrapped, "DESede", Cipher.SECRET_KEY).getEncoded()),
                    "unwrap mismatch");
        });
        step("Wrap a private key (PKCS#8) with AES-GCM-protected KEK", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();
            SecretKey kek = key("AES", 256);
            byte[] iv = random(12);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.WRAP_MODE, kek, new GCMParameterSpec(128, iv));
            byte[] wrapped = c.wrap(kp.getPrivate());
            c.init(Cipher.UNWRAP_MODE, kek, new GCMParameterSpec(128, iv));
            Key out = c.unwrap(wrapped, "EC", Cipher.PRIVATE_KEY);
            require(Arrays.equals(kp.getPrivate().getEncoded(), out.getEncoded()), "unwrap mismatch");
        });
    }

    private static void apiSurface() {
        section("Cipher API surface");
        step("Multi-part update() / doFinal()", () -> {
            SecretKey key = key("AES", 128);
            byte[] iv = random(16);
            Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] p1 = enc.update(PLAINTEXT, 0, 20);
            byte[] p2 = enc.update(PLAINTEXT, 20, PLAINTEXT.length - 20);
            byte[] p3 = enc.doFinal();
            java.io.ByteArrayOutputStream ct = new java.io.ByteArrayOutputStream();
            for (byte[] part : new byte[][] {p1, p2, p3}) {
                if (part != null) {
                    ct.write(part);
                }
            }
            Cipher dec = Cipher.getInstance("AES/CBC/PKCS5Padding");
            dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            require(Arrays.equals(PLAINTEXT, dec.doFinal(ct.toByteArray())), "round trip failed");
        });
        step("getBlockSize / getOutputSize / getAlgorithm / getIV / getParameters", () -> {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key("AES", 128));
            info("blockSize", c.getBlockSize());
            info("outputSize(100)", c.getOutputSize(100));
            info("algorithm", c.getAlgorithm());
            info("iv length", c.getIV().length);
            info("parameters", c.getParameters().getAlgorithm());
        });
        step("Cipher.getMaxAllowedKeyLength / getMaxAllowedParameterSpec", () -> {
            info("AES max key length", Cipher.getMaxAllowedKeyLength("AES"));
            info("AES max parameter spec", Cipher.getMaxAllowedParameterSpec("AES"));
        });
        step("doFinal(byte[], int, int, byte[], int) into caller buffer", () -> {
            SecretKey key = key("AES", 128);
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            byte[] out = new byte[c.getOutputSize(PLAINTEXT.length)];
            int n = c.doFinal(PLAINTEXT, 0, PLAINTEXT.length, out, 0);
            info("bytes written", n);
        });
        step("ByteBuffer doFinal", () -> {
            SecretKey key = key("AES", 128);
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, key);
            java.nio.ByteBuffer in = java.nio.ByteBuffer.wrap(PLAINTEXT);
            java.nio.ByteBuffer out = java.nio.ByteBuffer.allocate(c.getOutputSize(PLAINTEXT.length));
            c.doFinal(in, out);
            info("bytes written", out.position());
        });
        step("GCM IV reuse guard (re-init with same key+IV is rejected)", () -> {
            SecretKey key = key("AES", 128);
            byte[] iv = random(12);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            c.doFinal(PLAINTEXT);
            try {
                c.doFinal(PLAINTEXT);
                throw new IllegalStateException("IV reuse was not rejected");
            } catch (IllegalStateException e) {
                if (e.getMessage() != null && e.getMessage().equals("IV reuse was not rejected")) {
                    throw e;
                }
                info("result", "rejected as expected");
            }
        });
    }
}
