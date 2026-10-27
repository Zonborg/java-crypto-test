package cryptodemo.bouncycastle;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.step;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

/** BouncyCastle OpenPGP (bcpg): key generation, public-key and passphrase encryption, signatures and ASCII armor. */
public final class BcPgpDemo {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] PASSPHRASE = "pgp passphrase".toCharArray();
    private static final byte[] DATA = "secret message for the recipient".getBytes(StandardCharsets.UTF_8);

    private record Ring(PGPPublicKeyRing pub, PGPSecretKeyRing sec) {
    }

    private BcPgpDemo() {
    }

    public static void run() {
        if (Security.getProvider(BC) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        section("Key rings");
        Ring[] rsa = new Ring[1];
        Ring[] ec = new Ring[1];
        step("Generate an RSA-3072 key ring (certify/sign master + encryption subkey), protected by a passphrase", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
            kpg.initialize(3072);
            rsa[0] = ring("Alice <alice@example.com>",
                    new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kpg.generateKeyPair(), new Date()),
                    new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kpg.generateKeyPair(), new Date()));
            info("master key ID", Long.toHexString(rsa[0].pub().getPublicKey().getKeyID()));
            info("keys in ring", countKeys(rsa[0].pub()));
        });
        step("Generate an EC P-256 key ring (ECDSA master + ECDH encryption subkey)", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair signing = kpg.generateKeyPair();
            KeyPair encryption = kpg.generateKeyPair();
            ec[0] = ring("Bob <bob@example.com>",
                    new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, signing, new Date()),
                    new JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH,
                            new org.bouncycastle.openpgp.PGPKdfParameters(HashAlgorithmTags.SHA256,
                                    SymmetricKeyAlgorithmTags.AES_128),
                            encryption, new Date()));
            info("master key ID", Long.toHexString(ec[0].pub().getPublicKey().getKeyID()));
        });
        step("Export and re-import ASCII-armored public key ring", () -> {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            try (ArmoredOutputStream armor = new ArmoredOutputStream(bout)) {
                rsa[0].pub().encode(armor);
            }
            String text = bout.toString(StandardCharsets.US_ASCII);
            require(text.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"), "missing armor header");
            PGPPublicKeyRing parsed = (PGPPublicKeyRing) new JcaPGPObjectFactory(
                    PGPUtil.getDecoderStream(new ByteArrayInputStream(bout.toByteArray()))).nextObject();
            require(parsed.getPublicKey().getKeyID() == rsa[0].pub().getPublicKey().getKeyID(), "key ID differs");
        });

        section("Public-key encryption");
        for (String name : new String[] {"RSA", "EC"}) {
            Ring[] holder = name.equals("RSA") ? rsa : ec;
            for (int cipher : new int[] {PGPEncryptedData.AES_256, PGPEncryptedData.AES_128, PGPEncryptedData.CAMELLIA_256,
                    PGPEncryptedData.TWOFISH}) {
                step(name + " recipient, " + cipherName(cipher) + " (binary)", () -> {
                    byte[] message = encrypt(findEncryptionKey(holder[0].pub()), cipher, false, null);
                    require(Arrays.equals(DATA, decrypt(message, holder[0].sec())), "decrypted content differs");
                    info("message size", message.length + " bytes");
                });
            }
            step(name + " recipient, ASCII-armored message", () -> {
                byte[] message = encrypt(findEncryptionKey(holder[0].pub()), PGPEncryptedData.AES_256, true, null);
                require(new String(message, StandardCharsets.US_ASCII).startsWith("-----BEGIN PGP MESSAGE-----"),
                        "missing armor header");
                require(Arrays.equals(DATA, decrypt(message, holder[0].sec())), "decrypted content differs");
            });
        }

        section("Passphrase (symmetric) encryption");
        step("AES-256 with a salted, iterated S2K", () -> {
            byte[] message = encrypt(null, PGPEncryptedData.AES_256, false, PASSPHRASE);
            PGPEncryptedDataList list = encryptedList(message);
            PGPPBEEncryptedData pbe = (PGPPBEEncryptedData) list.get(0);
            InputStream clear = pbe.getDataStream(new JcePBEDataDecryptorFactoryBuilder(
                    new JcaPGPDigestCalculatorProviderBuilder().setProvider(BC).build()).setProvider(BC).build(PASSPHRASE));
            require(Arrays.equals(DATA, literal(clear)), "decrypted content differs");
        });

        section("Signatures");
        for (int hash : new int[] {HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA512,
                HashAlgorithmTags.SHA3_256}) {
            step("RSA signature with " + hashName(hash), () -> {
                PGPSecretKey signer = rsa[0].sec().getSecretKey();
                PGPPrivateKey priv = signer.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(
                        new JcaPGPDigestCalculatorProviderBuilder().setProvider(BC).build()).setProvider(BC).build(PASSPHRASE));
                PGPSignatureGenerator gen = new PGPSignatureGenerator(
                        new JcaPGPContentSignerBuilder(signer.getPublicKey().getAlgorithm(), hash).setProvider(BC),
                        signer.getPublicKey());
                gen.init(PGPSignature.BINARY_DOCUMENT, priv);
                gen.update(DATA);
                byte[] encoded = gen.generate().getEncoded();

                PGPSignature sig = ((PGPSignatureList) new JcaPGPObjectFactory(encoded).nextObject()).get(0);
                sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider(BC), signer.getPublicKey());
                sig.update(DATA);
                require(sig.verify(), "signature did not verify");

                PGPSignature tampered = ((PGPSignatureList) new JcaPGPObjectFactory(encoded).nextObject()).get(0);
                tampered.init(new JcaPGPContentVerifierBuilderProvider().setProvider(BC), signer.getPublicKey());
                tampered.update(Arrays.copyOf(DATA, DATA.length - 1));
                require(!tampered.verify(), "tampered data verified");
                info("signature packet", encoded.length + " bytes");
            });
        }
        step("ECDSA signature with SHA-256", () -> {
            PGPSecretKey signer = ec[0].sec().getSecretKey();
            PGPPrivateKey priv = signer.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(
                    new JcaPGPDigestCalculatorProviderBuilder().setProvider(BC).build()).setProvider(BC).build(PASSPHRASE));
            PGPSignatureGenerator gen = new PGPSignatureGenerator(
                    new JcaPGPContentSignerBuilder(signer.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256)
                            .setProvider(BC), signer.getPublicKey());
            gen.init(PGPSignature.BINARY_DOCUMENT, priv);
            gen.update(DATA);
            PGPSignature sig = gen.generate();
            sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider(BC), signer.getPublicKey());
            sig.update(DATA);
            require(sig.verify(), "signature did not verify");
        });
    }

    private static String hashName(int tag) {
        return switch (tag) {
            case HashAlgorithmTags.SHA256 -> "SHA-256";
            case HashAlgorithmTags.SHA384 -> "SHA-384";
            case HashAlgorithmTags.SHA512 -> "SHA-512";
            case HashAlgorithmTags.SHA3_256 -> "SHA3-256";
            default -> "hash " + tag;
        };
    }

    private static String cipherName(int tag) {
        return switch (tag) {
            case PGPEncryptedData.AES_128 -> "AES-128";
            case PGPEncryptedData.AES_256 -> "AES-256";
            case PGPEncryptedData.CAMELLIA_256 -> "Camellia-256";
            case PGPEncryptedData.TWOFISH -> "Twofish";
            default -> "cipher " + tag;
        };
    }

    private static int countKeys(PGPPublicKeyRing ring) {
        int n = 0;
        for (Iterator<PGPPublicKey> it = ring.getPublicKeys(); it.hasNext(); it.next()) {
            n++;
        }
        return n;
    }

    private static Ring ring(String userId, PGPKeyPair master, PGPKeyPair encryption) throws Exception {
        PGPDigestCalculator sha1 = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPDigestCalculator sha256 = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256);

        PGPSignatureSubpacketGenerator masterFlags = new PGPSignatureSubpacketGenerator();
        masterFlags.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        PGPSignatureSubpacketGenerator subFlags = new PGPSignatureSubpacketGenerator();
        subFlags.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        PGPKeyRingGenerator gen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, master, userId, sha1,
                masterFlags.generate(), null,
                new JcaPGPContentSignerBuilder(master.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256).setProvider(BC),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256).setProvider(BC).build(PASSPHRASE));
        gen.addSubKey(encryption, subFlags.generate(), null);
        return new Ring(gen.generatePublicKeyRing(), gen.generateSecretKeyRing());
    }

    private static PGPPublicKey findEncryptionKey(PGPPublicKeyRing ring) {
        for (Iterator<PGPPublicKey> it = ring.getPublicKeys(); it.hasNext();) {
            PGPPublicKey key = it.next();
            if (key.isEncryptionKey()) {
                return key;
            }
        }
        throw new IllegalStateException("no encryption key in ring");
    }

    /** Encrypts DATA to a public key, or with a passphrase when {@code passphrase} is non-null. */
    private static byte[] encrypt(PGPPublicKey recipient, int cipher, boolean armor, char[] passphrase) throws Exception {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        OutputStream out = armor ? new ArmoredOutputStream(bout) : bout;

        PGPEncryptedDataGenerator gen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(cipher)
                .setWithIntegrityPacket(true).setSecureRandom(RANDOM).setProvider(BC));
        if (passphrase != null) {
            gen.addMethod(new JcePBEKeyEncryptionMethodGenerator(passphrase).setProvider(BC));
        } else {
            gen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(recipient).setProvider(BC));
        }
        try (OutputStream encrypted = gen.open(out, new byte[4096])) {
            PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
            try (OutputStream compressed = compressor.open(encrypted)) {
                try (OutputStream literal = new PGPLiteralDataGenerator().open(compressed, PGPLiteralData.BINARY,
                        "message.txt", DATA.length, new Date())) {
                    literal.write(DATA);
                }
            }
        }
        out.close();
        return bout.toByteArray();
    }

    private static PGPEncryptedDataList encryptedList(byte[] message) throws Exception {
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(new ByteArrayInputStream(message)));
        Object first = factory.nextObject();
        return first instanceof PGPEncryptedDataList list ? list : (PGPEncryptedDataList) factory.nextObject();
    }

    private static byte[] decrypt(byte[] message, PGPSecretKeyRing secrets) throws Exception {
        PGPEncryptedDataList list = encryptedList(message);
        PGPPublicKeyEncryptedData encrypted = (PGPPublicKeyEncryptedData) list.getEncryptedDataObjects().next();
        PGPSecretKey secret = secrets.getSecretKey(encrypted.getKeyID());
        PGPPrivateKey priv = secret.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(
                new JcaPGPDigestCalculatorProviderBuilder().setProvider(BC).build()).setProvider(BC).build(PASSPHRASE));
        InputStream clear = encrypted.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BC).build(priv));
        byte[] plain = literal(clear);
        require(encrypted.isIntegrityProtected() && encrypted.verify(), "integrity check failed");
        return plain;
    }

    private static byte[] literal(InputStream clear) throws Exception {
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(clear);
        Object message = factory.nextObject();
        if (message instanceof PGPCompressedData compressed) {
            factory = new JcaPGPObjectFactory(compressed.getDataStream());
            message = factory.nextObject();
        }
        return ((PGPLiteralData) message).getInputStream().readAllBytes();
    }
}
