package cryptodemo;

import cryptodemo.bouncycastle.BcAsymmetricDemo;
import cryptodemo.bouncycastle.BcDigestMacDemo;
import cryptodemo.bouncycastle.BcKdfDemo;
import cryptodemo.bouncycastle.BcPgpDemo;
import cryptodemo.bouncycastle.BcPkixDemo;
import cryptodemo.bouncycastle.BcPostQuantumDemo;
import cryptodemo.bouncycastle.BcProviderDemo;
import cryptodemo.bouncycastle.BcSymmetricDemo;
import cryptodemo.jca.AlgorithmParametersDemo;
import cryptodemo.jca.CertificateDemo;
import cryptodemo.jca.KeyPairDemo;
import cryptodemo.jca.KeyStoreDemo;
import cryptodemo.jca.MessageDigestDemo;
import cryptodemo.jca.ProviderDemo;
import cryptodemo.jca.SecureRandomDemo;
import cryptodemo.jca.SignatureDemo;
import cryptodemo.jca.SignedObjectDemo;
import cryptodemo.jce.CipherDemo;
import cryptodemo.jce.CipherStreamDemo;
import cryptodemo.jce.KemDemo;
import cryptodemo.jce.KeyAgreementDemo;
import cryptodemo.jce.KeyDerivationDemo;
import cryptodemo.jce.KeyGeneratorDemo;
import cryptodemo.jce.MacDemo;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Runs every JCA/JCE demo. Optional arguments filter demos by name (case-insensitive substring),
 * e.g. {@code java cryptodemo.Main jca cipher}.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        Map<String, Runnable> demos = new LinkedHashMap<>();
        demos.put("JCA: Providers", ProviderDemo::run);
        demos.put("JCA: MessageDigest", MessageDigestDemo::run);
        demos.put("JCA: SecureRandom", SecureRandomDemo::run);
        demos.put("JCA: AlgorithmParameters", AlgorithmParametersDemo::run);
        demos.put("JCA: KeyPairGenerator / KeyFactory", KeyPairDemo::run);
        demos.put("JCA: Signature", SignatureDemo::run);
        demos.put("JCA: SignedObject", SignedObjectDemo::run);
        demos.put("JCA: KeyStore", KeyStoreDemo::run);
        demos.put("JCA: Certificates / CertPath", CertificateDemo::run);
        demos.put("JCE: Mac", MacDemo::run);
        demos.put("JCE: KeyGenerator / SecretKeyFactory", KeyGeneratorDemo::run);
        demos.put("JCE: Key Derivation (PBKDF2 / HKDF)", KeyDerivationDemo::run);
        demos.put("JCE: Cipher", CipherDemo::run);
        demos.put("JCE: Cipher streams / SealedObject", CipherStreamDemo::run);
        demos.put("JCE: KeyAgreement", KeyAgreementDemo::run);
        demos.put("JCE: KEM", KemDemo::run);
        demos.put("BC lightweight: Digests / XOFs / MACs", BcDigestMacDemo::run);
        demos.put("BC lightweight: Symmetric ciphers / AEAD / FPE", BcSymmetricDemo::run);
        demos.put("BC lightweight: RSA / EC / EdDSA / SM2 / agreement", BcAsymmetricDemo::run);
        demos.put("BC lightweight: KDFs / password hashing / DRBG", BcKdfDemo::run);
        demos.put("BC provider: JCA/JCE algorithms via \"BC\"", BcProviderDemo::run);
        demos.put("BC post-quantum: KEMs / signatures", BcPostQuantumDemo::run);
        demos.put("BC PKIX: X.509 / CSR / CRL / OCSP / CMS / PEM / keystores", BcPkixDemo::run);
        demos.put("BC OpenPGP: keys / encryption / signatures", BcPgpDemo::run);

        System.out.println("Java Cryptography Architecture (JCA) / Extension (JCE) Showcase");
        System.out.println("Java " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")");

        for (Map.Entry<String, Runnable> demo : demos.entrySet()) {
            if (!matches(demo.getKey(), args)) {
                continue;
            }
            DemoSupport.banner(demo.getKey());
            try {
                demo.getValue().run();
            } catch (RuntimeException | LinkageError e) {
                System.out.println("  [ABORTED] " + e);
            }
        }

        System.out.printf("%nSummary: %d succeeded, %d failed%n", DemoSupport.passed(), DemoSupport.failed());
    }

    private static boolean matches(String name, String[] filters) {
        if (filters.length == 0) {
            return true;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        for (String f : filters) {
            if (lower.contains(f.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }
}
