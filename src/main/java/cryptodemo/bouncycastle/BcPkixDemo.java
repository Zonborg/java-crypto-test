package cryptodemo.bouncycastle;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Set;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaRespID;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSAuthEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransAuthEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/** BouncyCastle PKIX (bcpkix): X.509, CSR, CRL, OCSP, CMS, PEM and BouncyCastle keystores. */
public final class BcPkixDemo {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final byte[] DATA = "contract text to protect".getBytes(StandardCharsets.UTF_8);

    private record Identity(KeyPair keys, X509Certificate cert) {
    }

    private BcPkixDemo() {
    }

    public static void run() {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        Identity root;
        Identity inter;
        Identity leaf;
        Identity ecLeaf;
        try {
            KeyPair rootKeys = ec("secp384r1");
            root = issue("CN=Demo Root CA,O=java-crypto-test", rootKeys, null, null, "SHA384withECDSA", true, 0);
            KeyPair interKeys = ec("secp256r1");
            inter = issue("CN=Demo Intermediate CA,O=java-crypto-test", interKeys, root.cert(), rootKeys.getPrivate(),
                    "SHA384withECDSA", true, 0);
            KeyPair leafKeys = rsa();
            leaf = issue("CN=leaf.example.com,O=java-crypto-test", leafKeys, inter.cert(), interKeys.getPrivate(),
                    "SHA256withECDSA", false, KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
            KeyPair ecKeys = ec("secp256r1");
            ecLeaf = issue("CN=ec.example.com,O=java-crypto-test", ecKeys, inter.cert(), interKeys.getPrivate(),
                    "SHA256withECDSA", false, KeyUsage.digitalSignature | KeyUsage.keyAgreement);
        } catch (Exception e) {
            throw new IllegalStateException("could not build the demo PKI", e);
        }

        certificates(root, inter, leaf);
        csrAndCrl(inter, leaf);
        ocsp(inter, leaf);
        pem(leaf);
        cms(leaf, ecLeaf);
        keyStores(root, inter, leaf);
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
        kpg.initialize(3072);
        return kpg.generateKeyPair();
    }

    private static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
        kpg.initialize(new ECGenParameterSpec(curve));
        return kpg.generateKeyPair();
    }

    /** Builds an X.509 v3 certificate; a null issuer certificate produces a self-signed certificate. */
    private static Identity issue(String dn, KeyPair subject, X509Certificate issuerCert, PrivateKey issuerKey,
            String sigAlg, boolean ca, int keyUsage) throws Exception {
        X500Name subjectName = new X500Name(dn);
        X500Name issuerName = issuerCert == null ? subjectName : new JcaX509CertificateHolder(issuerCert).getSubject();
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 24L * 3600 * 1000);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, new BigInteger(64, RANDOM),
                notBefore, notAfter, subjectName, subject.getPublic());
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : keyUsage));
        builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(subject.getPublic()));
        if (issuerCert != null) {
            builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCert));
        }
        if (!ca) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "example.com")));
        }
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider(BC)
                .build(issuerCert == null ? subject.getPrivate() : issuerKey);
        return new Identity(subject, new JcaX509CertificateConverter().setProvider(BC).getCertificate(builder.build(signer)));
    }

    private static void certificates(Identity root, Identity inter, Identity leaf) {
        section("X.509 certificates");
        step("Three-level chain: root (ECDSA P-384) -> intermediate (P-256) -> leaf (RSA-3072)", () -> {
            leaf.cert().verify(inter.cert().getPublicKey());
            inter.cert().verify(root.cert().getPublicKey());
            root.cert().verify(root.cert().getPublicKey());
            info("leaf subject", leaf.cert().getSubjectX500Principal());
            info("leaf signature algorithm", leaf.cert().getSigAlgName());
        });
        step("PKIX path validation with the BC CertPathValidator", () -> {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);
            CertPath path = cf.generateCertPath(List.of(leaf.cert(), inter.cert()));
            PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(root.cert(), null)));
            params.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX", BC).validate(path, params);
            info("result", "path validated");
        });
        for (String[] alg : new String[][] {{"Ed25519", "Ed25519"}, {"Ed448", "Ed448"}, {"ML-DSA-65", "ML-DSA-65"},
                {"SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-128F"}, {"Falcon-512", "Falcon-512"}}) {
            step("Self-signed certificate with " + alg[0] + " key", () -> {
                KeyPair kp = KeyPairGenerator.getInstance(alg[0], BC).generateKeyPair();
                Identity id = issue("CN=" + alg[0] + " test", kp, null, null, alg[1], false, KeyUsage.digitalSignature);
                id.cert().verify(id.cert().getPublicKey());
                info(alg[0], "signature algorithm " + id.cert().getSigAlgName());
            });
        }
    }

    private static void csrAndCrl(Identity inter, Identity leaf) {
        section("PKCS#10 certification requests and CRLs");
        step("Create and verify a PKCS#10 CSR", () -> {
            KeyPair kp = ec("secp256r1");
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(kp.getPrivate());
            PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                    new X500Name("CN=csr.example.com,O=java-crypto-test"), kp.getPublic()).build(signer);
            require(csr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic())),
                    "CSR signature invalid");
            info("subject", csr.getSubject());
        });
        step("Create a CRL revoking the leaf and check it", () -> {
            JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(inter.cert().getSubjectX500Principal(), new Date());
            builder.setNextUpdate(new Date(System.currentTimeMillis() + 3600_000));
            builder.addCRLEntry(leaf.cert().getSerialNumber(), new Date(), CRLReason.keyCompromise);
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC)
                    .build(inter.keys().getPrivate());
            X509CRLHolder holder = builder.build(signer);
            X509CRL crl = new JcaX509CRLConverter().setProvider(BC).getCRL(holder);
            crl.verify(inter.cert().getPublicKey());
            require(crl.isRevoked(leaf.cert()), "leaf not reported as revoked");
            info("revoked entries", crl.getRevokedCertificates().size());
        });
    }

    private static void ocsp(Identity inter, Identity leaf) {
        section("OCSP");
        step("Build an OCSP request, sign a response, verify it", () -> {
            DigestCalculator sha1 = new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()
                    .get(CertificateID.HASH_SHA1);
            CertificateID id = new CertificateID(sha1, new JcaX509CertificateHolder(inter.cert()),
                    leaf.cert().getSerialNumber());
            OCSPReq request = new OCSPReqBuilder().addRequest(id).build();
            require(new OCSPReq(request.getEncoded()).getRequestList().length == 1, "request did not round trip");

            BasicOCSPRespBuilder responder = new BasicOCSPRespBuilder(new JcaRespID(inter.cert().getSubjectX500Principal()));
            responder.addResponse(id, CertificateStatus.GOOD);
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC)
                    .build(inter.keys().getPrivate());
            BasicOCSPResp basic = responder.build(signer,
                    new X509CertificateHolder[] {new JcaX509CertificateHolder(inter.cert())}, new Date());
            OCSPResp response = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic);

            BasicOCSPResp parsed = (BasicOCSPResp) new OCSPResp(response.getEncoded()).getResponseObject();
            require(parsed.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC)
                    .build(inter.cert().getPublicKey())), "OCSP signature invalid");
            require(parsed.getResponses()[0].getCertStatus() == CertificateStatus.GOOD, "status not good");
            info("status", "GOOD, signed by " + inter.cert().getSubjectX500Principal());
        });
    }

    private static void pem(Identity leaf) {
        section("PEM and PKCS#8 encodings");
        step("Write and parse a certificate", () -> {
            StringWriter sw = new StringWriter();
            try (JcaPEMWriter w = new JcaPEMWriter(sw)) {
                w.writeObject(leaf.cert());
            }
            try (PEMParser parser = new PEMParser(new StringReader(sw.toString()))) {
                X509CertificateHolder holder = (X509CertificateHolder) parser.readObject();
                require(holder.getSubject().equals(new JcaX509CertificateHolder(leaf.cert()).getSubject()), "subject differs");
            }
            info("PEM header", sw.toString().lines().findFirst().orElse(""));
        });
        step("Encrypted PKCS#8 private key (PBES2, AES-256-CBC)", () -> {
            StringWriter sw = new StringWriter();
            JceOpenSSLPKCS8EncryptorBuilder enc = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                    .setProvider(BC).setPasssword(PASSWORD);
            try (JcaPEMWriter w = new JcaPEMWriter(sw)) {
                w.writeObject(new JcaPKCS8Generator(leaf.keys().getPrivate(), enc.build()));
            }
            try (PEMParser parser = new PEMParser(new StringReader(sw.toString()))) {
                PKCS8EncryptedPrivateKeyInfo info = (PKCS8EncryptedPrivateKeyInfo) parser.readObject();
                PrivateKey key = new JcaPEMKeyConverter().setProvider(BC).getPrivateKey(info.decryptPrivateKeyInfo(
                        new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(BC).build(PASSWORD)));
                require(key.equals(leaf.keys().getPrivate()), "decrypted key differs");
            }
            info("PEM header", sw.toString().lines().findFirst().orElse(""));
        });
        step("Legacy OpenSSL encrypted key (Proc-Type / DEK-Info, AES-256-CBC)", () -> {
            StringWriter sw = new StringWriter();
            try (JcaPEMWriter w = new JcaPEMWriter(sw)) {
                w.writeObject(leaf.keys().getPrivate(), new JcePEMEncryptorBuilder("AES-256-CBC").setProvider(BC)
                        .setSecureRandom(RANDOM).build(PASSWORD));
            }
            try (PEMParser parser = new PEMParser(new StringReader(sw.toString()))) {
                PEMEncryptedKeyPair encrypted = (PEMEncryptedKeyPair) parser.readObject();
                PEMKeyPair pair = encrypted.decryptKeyPair(new JcePEMDecryptorProviderBuilder().setProvider(BC).build(PASSWORD));
                PrivateKey key = new JcaPEMKeyConverter().setProvider(BC).getPrivateKey(pair.getPrivateKeyInfo());
                require(key.getAlgorithm().equals(leaf.keys().getPrivate().getAlgorithm()), "algorithm differs");
            }
            info("PEM header", sw.toString().lines().findFirst().orElse(""));
        });
    }

    private static void cms(Identity rsaId, Identity ecId) {
        section("CMS / PKCS#7");
        step("SignedData (encapsulated, RSA-PSS-free SHA256withRSA)", () -> {
            CMSSignedData signed = sign(rsaId, "SHA256withRSA", true);
            verify(signed, rsaId);
            info("encoded size", signed.getEncoded().length + " bytes");
        });
        step("SignedData (detached, ECDSA)", () -> {
            CMSSignedData detached = sign(ecId, "SHA256withECDSA", false);
            CMSSignedData reparsed = new CMSSignedData(new CMSProcessableByteArray(DATA), detached.getEncoded());
            verify(reparsed, ecId);
        });
        step("SignedData with Ed25519", () -> {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519", BC).generateKeyPair();
            Identity id = issue("CN=ed25519 signer", kp, null, null, "Ed25519", false, KeyUsage.digitalSignature);
            verify(sign(id, "Ed25519", true), id);
        });
        step("SignedData with ML-DSA-65", () -> {
            KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", BC).generateKeyPair();
            Identity id = issue("CN=ml-dsa signer", kp, null, null, "ML-DSA-65", false, KeyUsage.digitalSignature);
            verify(sign(id, "ML-DSA-65", true), id);
        });
        step("EnvelopedData: RSA key transport + AES-256-CBC", () -> {
            CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
            gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(rsaId.cert()).setProvider(BC));
            CMSEnvelopedData env = gen.generate(new CMSProcessableByteArray(DATA),
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BC).build());
            RecipientInformation ri = new CMSEnvelopedData(env.getEncoded()).getRecipientInfos().getRecipients()
                    .iterator().next();
            byte[] plain = ri.getContent(new JceKeyTransEnvelopedRecipient(rsaId.keys().getPrivate()).setProvider(BC));
            require(Arrays.equals(DATA, plain), "decrypted content differs");
        });
        step("AuthEnvelopedData: RSA key transport + AES-256-GCM", () -> {
            CMSAuthEnvelopedDataGenerator gen = new CMSAuthEnvelopedDataGenerator();
            gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(rsaId.cert()).setProvider(BC));
            CMSAuthEnvelopedData env = gen.generate(new CMSProcessableByteArray(DATA),
                    (OutputAEADEncryptor) new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_GCM).setProvider(BC).build());
            RecipientInformation ri = new CMSAuthEnvelopedData(env.getEncoded()).getRecipientInfos().getRecipients()
                    .iterator().next();
            byte[] plain = ri.getContent(new JceKeyTransAuthEnvelopedRecipient(rsaId.keys().getPrivate()).setProvider(BC));
            require(Arrays.equals(DATA, plain), "decrypted content differs");
        });
        step("EnvelopedData: password recipient (PBKDF2)", () -> {
            CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
            gen.addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(CMSAlgorithm.AES256_CBC, PASSWORD)
                    .setProvider(BC).setSaltAndIterationCount(randomBytes(16), 10_000));
            CMSEnvelopedData env = gen.generate(new CMSProcessableByteArray(DATA),
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BC).build());
            RecipientInformation ri = new CMSEnvelopedData(env.getEncoded()).getRecipientInfos().getRecipients()
                    .iterator().next();
            require(Arrays.equals(DATA, ri.getContent(new JcePasswordEnvelopedRecipient(PASSWORD).setProvider(BC))),
                    "decrypted content differs");
        });
        step("EnvelopedData: ECDH key agreement (ECDH-SHA256KDF + AES-128 key wrap)", () -> {
            KeyPair sender = ec("secp256r1");
            CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
            gen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECDH_SHA256KDF,
                    sender.getPrivate(), sender.getPublic(), CMSAlgorithm.AES128_WRAP).addRecipient(ecId.cert())
                    .setProvider(BC));
            CMSEnvelopedData env = gen.generate(new CMSProcessableByteArray(DATA),
                    new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BC).build());
            RecipientInformation ri = new CMSEnvelopedData(env.getEncoded()).getRecipientInfos().getRecipients()
                    .iterator().next();
            byte[] plain = ri.getContent(new JceKeyAgreeEnvelopedRecipient(ecId.keys().getPrivate()).setProvider(BC));
            require(Arrays.equals(DATA, plain), "decrypted content differs");
        });
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static CMSSignedData sign(Identity id, String sigAlg, boolean encapsulate) throws Exception {
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider(BC).build(id.keys().getPrivate());
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider(BC).build()).build(signer, id.cert()));
        gen.addCertificates(new JcaCertStore(List.of(id.cert())));
        return gen.generate(new CMSProcessableByteArray(DATA), encapsulate);
    }

    private static void verify(CMSSignedData signed, Identity id) throws Exception {
        SignerInformation si = signed.getSignerInfos().getSigners().iterator().next();
        require(si.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BC).build(id.cert())),
                "CMS signature invalid");
        info("signer digest OID / signature OID", si.getDigestAlgOID() + " / " + si.getEncryptionAlgOID());
    }

    private static void keyStores(Identity root, Identity inter, Identity leaf) {
        section("BouncyCastle keystores");
        for (String type : List.of("BCFKS", "BKS", "PKCS12")) {
            step(type, () -> {
                KeyStore ks = KeyStore.getInstance(type, BC);
                ks.load(null, null);
                Certificate[] chain = {leaf.cert(), inter.cert(), root.cert()};
                ks.setKeyEntry("leaf", leaf.keys().getPrivate(), PASSWORD, chain);
                ks.setCertificateEntry("root", root.cert());

                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ks.store(out, PASSWORD);
                KeyStore reloaded = KeyStore.getInstance(type, BC);
                reloaded.load(new ByteArrayInputStream(out.toByteArray()), PASSWORD);
                require(reloaded.getKey("leaf", PASSWORD).equals(leaf.keys().getPrivate()), "key differs");
                require(reloaded.getCertificateChain("leaf").length == 3, "chain lost");
                info(type + " size", out.size() + " bytes");
            });
        }
        step("UBER (secret key entries)", () -> {
            KeyStore ks = KeyStore.getInstance("UBER", BC);
            ks.load(null, null);
            SecretKey aes = KeyGenerator.getInstance("AES", BC).generateKey();
            ks.setKeyEntry("aes", aes, PASSWORD, null);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ks.store(out, PASSWORD);
            KeyStore reloaded = KeyStore.getInstance("UBER", BC);
            reloaded.load(new ByteArrayInputStream(out.toByteArray()), PASSWORD);
            require(Arrays.equals(aes.getEncoded(), reloaded.getKey("aes", PASSWORD).getEncoded()), "key differs");
            info("UBER size", shortHex(Arrays.copyOf(out.toByteArray(), 16)));
        });
    }
}
