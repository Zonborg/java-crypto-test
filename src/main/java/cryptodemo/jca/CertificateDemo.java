package cryptodemo.jca;

import static cryptodemo.DemoSupport.hex;
import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.step;

import cryptodemo.TestCredentials;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/** java.security.cert: CertificateFactory, CertPath, CertPathValidator, CertPathBuilder and CertStore. */
public final class CertificateDemo {

    private CertificateDemo() {
    }

    public static void run() {
        section("CertificateFactory (X.509)");
        step("Parse a PEM certificate and read its fields", () -> {
            X509Certificate cert = parsePem(toPem(rsaCert()));
            info("subject", cert.getSubjectX500Principal());
            info("issuer", cert.getIssuerX500Principal());
            info("serial", cert.getSerialNumber().toString(16));
            info("valid", cert.getNotBefore() + " -> " + cert.getNotAfter());
            info("signature algorithm", cert.getSigAlgName());
            info("public key", cert.getPublicKey().getAlgorithm());
            info("basic constraints (path length, -1 = not CA)", cert.getBasicConstraints());
            info("version", cert.getVersion());
        });
        step("Parse DER (binary) encoding", () -> {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(rsaCert().getEncoded()));
            require(cert.equals(rsaCert()), "decoded certificate differs");
        });
        step("checkValidity() and checkValidity(Date)", () -> {
            X509Certificate cert = rsaCert();
            cert.checkValidity();
            try {
                cert.checkValidity(new java.util.Date(0));
                throw new IllegalStateException("expired date accepted");
            } catch (java.security.cert.CertificateNotYetValidException expected) {
                info("1970 check", "rejected as expected");
            }
        });
        step("verify(PublicKey): self-signed certificate signature", () -> {
            X509Certificate cert = rsaCert();
            cert.verify(cert.getPublicKey());
        });
        step("SHA-256 fingerprint", () -> {
            byte[] fp = MessageDigest.getInstance("SHA-256").digest(rsaCert().getEncoded());
            info("fingerprint", hex(fp));
        });
        step("Extensions: key usage, critical OIDs, subject alternative names", () -> {
            X509Certificate cert = ecCert();
            info("key usage", java.util.Arrays.toString(cert.getKeyUsage()));
            info("critical OIDs", cert.getCriticalExtensionOIDs());
            info("non-critical OIDs", cert.getNonCriticalExtensionOIDs());
            info("SANs", cert.getSubjectAlternativeNames());
        });
        step("Verify a signature using the certificate's public key", () -> {
            KeyStore ks = TestCredentials.load();
            PrivateKey key = (PrivateKey) ks.getKey(TestCredentials.EC_ALIAS, TestCredentials.PASSWORD);
            byte[] data = "signed with certificate-bound key".getBytes(StandardCharsets.UTF_8);
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(key);
            signer.update(data);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(ecCert());
            verifier.update(data);
            require(verifier.verify(sig), "verification via certificate failed");
        });

        section("CertPath");
        step("generateCertPath / getEncodings / PkiPath round trip", () -> {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath path = cf.generateCertPath(List.of(rsaCert()));
            info("type", path.getType());
            info("length", path.getCertificates().size());
            info("encodings", java.util.Collections.list(
                    java.util.Collections.enumeration(iteratorToList(path.getEncodings()))));
            CertPath decoded = cf.generateCertPath(new ByteArrayInputStream(path.getEncoded("PkiPath")), "PkiPath");
            require(path.equals(decoded), "decoded path differs");
        });
        step("CertPathValidator (PKIX) with a TrustAnchor", () -> {
            X509Certificate cert = rsaCert();
            CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(cert));
            PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(cert, null)));
            params.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX").validate(path, params);
            info("result", "path validated");
        });
        step("CertPathBuilder (PKIX) with CertStore and X509CertSelector", () -> {
            X509Certificate cert = ecCert();
            CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(List.of(cert)));
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(cert);
            PKIXBuilderParameters params = new PKIXBuilderParameters(Set.of(new TrustAnchor(cert, null)), target);
            params.addCertStore(store);
            params.setRevocationEnabled(false);
            CertPathBuilderResult result = CertPathBuilder.getInstance("PKIX").build(params);
            info("trust anchor", ((PKIXCertPathBuilderResult) result).getTrustAnchor().getTrustedCert()
                    .getSubjectX500Principal());
        });
        step("CertStore.getCertificates(selector)", () -> {
            X509Certificate rsa = rsaCert();
            CertStore store = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(List.of(rsa, ecCert())));
            X509CertSelector selector = new X509CertSelector();
            selector.setSubject(rsa.getSubjectX500Principal());
            info("matches", store.getCertificates(selector).size());
        });
    }

    private static List<String> iteratorToList(java.util.Iterator<String> it) {
        java.util.List<String> out = new java.util.ArrayList<>();
        it.forEachRemaining(out::add);
        return out;
    }

    private static X509Certificate rsaCert() throws Exception {
        return (X509Certificate) TestCredentials.load().getCertificate(TestCredentials.RSA_ALIAS);
    }

    private static X509Certificate ecCert() throws Exception {
        return (X509Certificate) TestCredentials.load().getCertificate(TestCredentials.EC_ALIAS);
    }

    private static String toPem(X509Certificate cert) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }

    private static X509Certificate parsePem(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }
}
