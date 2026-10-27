package cryptodemo.jca;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.skip;
import static cryptodemo.DemoSupport.step;

import cryptodemo.TestCredentials;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

/** java.security.KeyStore: PKCS12, JKS, JCEKS, Windows stores and the default CA store. */
public final class KeyStoreDemo {

    private static final char[] PASSWORD = TestCredentials.PASSWORD;

    private KeyStoreDemo() {
    }

    public static void run() {
        section("Defaults");
        step("KeyStore.getDefaultType()", () -> info("default type", KeyStore.getDefaultType()));

        section("PKCS12");
        step("Create, populate, store, reload", () -> {
            KeyStore source = TestCredentials.load();
            PrivateKey rsaKey = (PrivateKey) source.getKey(TestCredentials.RSA_ALIAS, PASSWORD);
            Certificate[] rsaChain = source.getCertificateChain(TestCredentials.RSA_ALIAS);

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("rsa-key", rsaKey, PASSWORD, rsaChain);
            ks.setCertificateEntry("rsa-trusted", rsaChain[0]);
            ks.setEntry("aes-secret", new KeyStore.SecretKeyEntry(KeyGenerator.getInstance("AES").generateKey()),
                    new KeyStore.PasswordProtection(PASSWORD, "PBEWithHmacSHA256AndAES_256",
                            new PBEParameterSpec(randomBytes(16), 100_000, new IvParameterSpec(randomBytes(16)))));
            require(ks.size() == 3, "unexpected entry count " + ks.size());

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, PASSWORD);
            info("serialized size", out.size() + " bytes");

            KeyStore reloaded = KeyStore.getInstance("PKCS12");
            reloaded.load(new ByteArrayInputStream(out.toByteArray()), PASSWORD);
            require(reloaded.size() == 3, "reload lost entries");
            info("aliases", Collections.list(reloaded.aliases()));
        });
        step("Query: containsAlias / isKeyEntry / isCertificateEntry / getCreationDate / getCertificateAlias", () -> {
            KeyStore ks = TestCredentials.load();
            require(ks.containsAlias(TestCredentials.RSA_ALIAS), "alias missing");
            require(ks.isKeyEntry(TestCredentials.RSA_ALIAS), "not a key entry");
            require(!ks.isCertificateEntry(TestCredentials.RSA_ALIAS), "unexpected cert entry");
            Date created = ks.getCreationDate(TestCredentials.RSA_ALIAS);
            Certificate cert = ks.getCertificate(TestCredentials.RSA_ALIAS);
            info("created", created);
            info("alias by certificate", ks.getCertificateAlias(cert));
            info("entryInstanceOf PrivateKeyEntry", ks.entryInstanceOf(TestCredentials.RSA_ALIAS,
                    KeyStore.PrivateKeyEntry.class));
        });
        step("getEntry: PrivateKeyEntry and TrustedCertificateEntry", () -> {
            KeyStore ks = TestCredentials.load();
            KeyStore.PrivateKeyEntry pke = (KeyStore.PrivateKeyEntry) ks.getEntry(TestCredentials.EC_ALIAS,
                    new KeyStore.PasswordProtection(PASSWORD));
            info("EC private key", pke.getPrivateKey().getAlgorithm());
            info("chain length", pke.getCertificateChain().length);

            KeyStore copy = KeyStore.getInstance("PKCS12");
            copy.load(null, null);
            copy.setEntry("trusted", new KeyStore.TrustedCertificateEntry(pke.getCertificate()), null);
            require(copy.getEntry("trusted", null) instanceof KeyStore.TrustedCertificateEntry, "wrong entry type");
        });
        step("deleteEntry", () -> {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setCertificateEntry("temp", TestCredentials.load().getCertificate(TestCredentials.EC_ALIAS));
            ks.deleteEntry("temp");
            require(ks.size() == 0, "entry not deleted");
        });
        step("Recover secret key entry", () -> {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            SecretKey aes = KeyGenerator.getInstance("AES").generateKey();
            ks.setEntry("k", new KeyStore.SecretKeyEntry(aes), new KeyStore.PasswordProtection(PASSWORD));
            Key back = ks.getKey("k", PASSWORD);
            require(Arrays.equals(aes.getEncoded(), back.getEncoded()), "key mismatch");
        });
        step("KeyStore.Builder with PasswordProtection", () -> {
            KeyStore ks = KeyStore.Builder.newInstance(TestCredentials.load(), new KeyStore.PasswordProtection(PASSWORD))
                    .getKeyStore();
            info("size", ks.size());
        });
        step("Wrong password is rejected", () -> {
            KeyStore ks = TestCredentials.load();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, PASSWORD);
            try {
                KeyStore.getInstance("PKCS12").load(new ByteArrayInputStream(out.toByteArray()), "wrong".toCharArray());
                throw new IllegalStateException("wrong password was accepted");
            } catch (java.io.IOException expected) {
                info("result", "rejected as expected");
            }
        });

        section("Other keystore types");
        step("JKS (legacy Java KeyStore)", () -> {
            KeyStore source = TestCredentials.load();
            KeyStore jks = KeyStore.getInstance("JKS");
            jks.load(null, null);
            jks.setKeyEntry("rsa", source.getKey(TestCredentials.RSA_ALIAS, PASSWORD), PASSWORD,
                    source.getCertificateChain(TestCredentials.RSA_ALIAS));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            jks.store(out, PASSWORD);
            info("serialized size", out.size() + " bytes");
        });
        step("JCEKS (supports secret keys)", () -> {
            KeyStore jceks = KeyStore.getInstance("JCEKS");
            jceks.load(null, null);
            jceks.setKeyEntry("aes", KeyGenerator.getInstance("AES").generateKey(), PASSWORD, null);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            jceks.store(out, PASSWORD);
            KeyStore reloaded = KeyStore.getInstance("JCEKS");
            reloaded.load(new ByteArrayInputStream(out.toByteArray()), PASSWORD);
            require(reloaded.getKey("aes", PASSWORD) != null, "secret key missing");
        });
        step("Default CA store (cacerts) via KeyStore.getInstance(File, char[])", () -> {
            File cacerts = Path.of(System.getProperty("java.home"), "lib", "security", "cacerts").toFile();
            KeyStore ks = KeyStore.getInstance(cacerts, PASSWORD);
            info("type", ks.getType());
            info("trusted CAs", ks.size());
        });
        if (isWindows()) {
            step("Windows-MY (current user personal store)", () -> {
                KeyStore ks = KeyStore.getInstance("Windows-MY");
                ks.load(null, null);
                info("entries", ks.size());
            });
            step("Windows-ROOT (trusted root CAs)", () -> {
                KeyStore ks = KeyStore.getInstance("Windows-ROOT");
                ks.load(null, null);
                info("entries", ks.size());
            });
        } else {
            skip("Windows-MY / Windows-ROOT", "Windows only");
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win");
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }
}
