package cryptodemo;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/** Builds throwaway RSA and EC key/certificate pairs with the JDK's own keytool, so no key material is committed. */
public final class TestCredentials {

    public static final char[] PASSWORD = "changeit".toCharArray();
    public static final String RSA_ALIAS = "rsa";
    public static final String EC_ALIAS = "ec";

    private static KeyStore cached;

    private TestCredentials() {
    }

    /** A PKCS#12 keystore holding self-signed "rsa" and "ec" private key entries. */
    public static synchronized KeyStore load() throws Exception {
        if (cached != null) {
            return cached;
        }
        Path dir = Files.createTempDirectory("java-crypto-test");
        try {
            Path store = dir.resolve("demo.p12");
            genKeyPair(store, RSA_ALIAS, "RSA", List.of("-keysize", "2048", "-sigalg", "SHA256withRSA"));
            genKeyPair(store, EC_ALIAS, "EC", List.of("-groupname", "secp256r1", "-sigalg", "SHA256withECDSA"));

            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(store)) {
                ks.load(in, PASSWORD);
            }
            cached = ks;
            return ks;
        } finally {
            try (Stream<Path> files = Files.walk(dir)) {
                files.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    private static void genKeyPair(Path store, String alias, String keyAlg, List<String> extra)
            throws IOException, InterruptedException {
        String exe = System.getProperty("os.name").toLowerCase().contains("win") ? "keytool.exe" : "keytool";
        List<String> cmd = new java.util.ArrayList<>(List.of(
                Path.of(System.getProperty("java.home"), "bin", exe).toString(),
                "-genkeypair", "-alias", alias, "-keyalg", keyAlg,
                "-dname", "CN=Crypto Demo " + alias.toUpperCase() + ", O=java-crypto-test",
                "-validity", "30", "-ext", "bc:c",
                "-storetype", "PKCS12", "-keystore", store.toString(), "-storepass", new String(PASSWORD)));
        cmd.addAll(extra);

        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes());
        if (!p.waitFor(60, TimeUnit.SECONDS) || p.exitValue() != 0) {
            throw new IOException("keytool failed: " + output);
        }
    }
}
