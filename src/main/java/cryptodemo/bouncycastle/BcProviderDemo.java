package cryptodemo.bouncycastle;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;

/** BouncyCastle as a JCA/JCE provider ("BC"): the same JDK APIs, with BouncyCastle's algorithms behind them. */
public final class BcProviderDemo {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] MSG = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);

    private BcProviderDemo() {
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    public static void run() {
        step("Register BouncyCastleProvider", () -> {
            if (Security.getProvider(BC) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            Provider p = Security.getProvider(BC);
            info("provider", p.getName() + " " + p.getVersionStr());
            Map<String, Integer> counts = new TreeMap<>();
            for (Provider.Service s : p.getServices()) {
                counts.merge(s.getType(), 1, Integer::sum);
            }
            info("services by type", counts);
        });
        digests();
        macs();
        ciphers();
        pbe();
        signatures();
        keyAgreement();
        ecies();
    }

    private static void digests() {
        section("MessageDigest");
        for (String alg : List.of("MD2", "MD4", "MD5", "SHA-1", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512",
                "Keccak-256", "Keccak-512", "SHAKE128-256", "SHAKE256-512", "RIPEMD128", "RIPEMD160", "RIPEMD256",
                "RIPEMD320", "Whirlpool", "Tiger", "GOST3411", "GOST3411-2012-256", "GOST3411-2012-512", "SM3",
                "BLAKE2B-256", "BLAKE2B-512", "BLAKE2S-256", "BLAKE3-256", "SKEIN-256-256", "SKEIN-512-512",
                "SKEIN-1024-1024", "DSTU7564-256", "DSTU7564-512", "Haraka-256")) {
            step(alg, () -> {
                MessageDigest md = MessageDigest.getInstance(alg, BC);
                byte[] input = alg.startsWith("Haraka") ? new byte[32] : MSG;
                info(alg + " (" + md.getDigestLength() + " bytes)", shortHex(md.digest(input)));
            });
        }
    }

    private static void macs() {
        section("Mac");
        for (String alg : List.of("HMACSHA1", "HMACSHA256", "HMACSHA3-256", "HMACRIPEMD160", "HMACWhirlpool",
                "HMACKeccak256", "HMACSM3", "HMACGOST3411", "AESCMAC", "Poly1305-AES", "SipHash",
                "SipHash-4-8", "SipHash128", "Skein-MAC-512-512", "DESedeMAC")) {
            step(alg, () -> {
                Mac mac = Mac.getInstance(alg, BC);
                int keyLen = alg.startsWith("DESede") ? 24 : alg.startsWith("Poly1305") ? 32 : 16;
                SecretKey key = new SecretKeySpec(random(keyLen), alg);
                if (alg.startsWith("Poly1305")) {
                    mac.init(key, new IvParameterSpec(random(16)));
                } else {
                    mac.init(key);
                }
                info(alg + " (" + mac.getMacLength() + " bytes)", shortHex(mac.doFinal(MSG)));
            });
        }
    }

    private static void ciphers() {
        section("Cipher (block ciphers and modes)");
        for (String alg : List.of("AES", "Twofish", "Serpent", "Camellia", "ARIA", "SM4", "SEED", "CAST6", "RC6",
                "Noekeon", "Blowfish", "CAST5", "IDEA", "DESede")) {
            step(alg + "/CBC/PKCS7Padding", () -> {
                int keyLen = alg.equals("DESede") ? 24 : 16;
                SecretKey key = new SecretKeySpec(random(keyLen), alg);
                Cipher enc = Cipher.getInstance(alg + "/CBC/PKCS7Padding", BC);
                enc.init(Cipher.ENCRYPT_MODE, key);
                byte[] ct = enc.doFinal(MSG);
                Cipher dec = Cipher.getInstance(alg + "/CBC/PKCS7Padding", BC);
                dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(enc.getIV()));
                require(Arrays.equals(MSG, dec.doFinal(ct)), "round trip failed");
                info(alg, shortHex(ct));
            });
        }
        for (String mode : List.of("CTR", "CFB", "OFB", "CTS", "CBC", "ECB")) {
            step("AES/" + mode, () -> {
                String padding = mode.equals("CBC") || mode.equals("ECB") ? "PKCS7Padding" : "NoPadding";
                SecretKey key = new SecretKeySpec(random(32), "AES");
                Cipher enc = Cipher.getInstance("AES/" + mode + "/" + padding, BC);
                enc.init(Cipher.ENCRYPT_MODE, key);
                byte[] ct = enc.doFinal(MSG);
                Cipher dec = Cipher.getInstance("AES/" + mode + "/" + padding, BC);
                if (mode.equals("ECB")) {
                    dec.init(Cipher.DECRYPT_MODE, key);
                } else {
                    dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(enc.getIV()));
                }
                require(Arrays.equals(MSG, dec.doFinal(ct)), "round trip failed");
            });
        }
        for (String mode : List.of("GCM", "CCM", "EAX", "OCB", "GCM-SIV")) {
            step("AES/" + mode + "/NoPadding (AEAD)", () -> {
                SecretKey key = new SecretKeySpec(random(32), "AES");
                int nonceLen = mode.equals("EAX") ? 16 : 12;
                byte[] nonce = random(nonceLen);
                Cipher enc = Cipher.getInstance("AES/" + mode + "/NoPadding", BC);
                enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                enc.updateAAD("aad".getBytes(StandardCharsets.UTF_8));
                byte[] ct = enc.doFinal(MSG);
                Cipher dec = Cipher.getInstance("AES/" + mode + "/NoPadding", BC);
                dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                dec.updateAAD("aad".getBytes(StandardCharsets.UTF_8));
                require(Arrays.equals(MSG, dec.doFinal(ct)), "round trip failed");
                info(mode, shortHex(ct));
            });
        }
        record Stream(String alg, int keyLen, int ivLen) {
        }
        for (Stream s : List.of(new Stream("ChaCha7539", 32, 12), new Stream("ChaCha", 32, 8),
                new Stream("Salsa20", 32, 8), new Stream("XSalsa20", 32, 24), new Stream("HC128", 16, 16),
                new Stream("HC256", 32, 32), new Stream("Grainv1", 10, 8), new Stream("Grain128", 16, 12),
                new Stream("ZUC-128", 16, 16), new Stream("VMPC", 16, 16), new Stream("RC4", 16, 0),
                new Stream("ChaCha20-Poly1305", 32, 12))) {
            step(s.alg() + " (stream cipher)", () -> {
                SecretKey key = new SecretKeySpec(random(s.keyLen()), s.alg().startsWith("ChaCha20") ? "ChaCha20" : s.alg());
                byte[] iv = random(s.ivLen());
                Cipher enc = Cipher.getInstance(s.alg(), BC);
                if (s.ivLen() == 0) {
                    enc.init(Cipher.ENCRYPT_MODE, key);
                } else {
                    enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
                }
                byte[] ct = enc.doFinal(MSG);
                Cipher dec = Cipher.getInstance(s.alg(), BC);
                if (s.ivLen() == 0) {
                    dec.init(Cipher.DECRYPT_MODE, key);
                } else {
                    dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                }
                require(Arrays.equals(MSG, dec.doFinal(ct)), "round trip failed");
            });
        }
        step("AESWRAP / AESWRAPPAD key wrapping", () -> {
            SecretKey kek = KeyGenerator.getInstance("AES", BC).generateKey();
            for (String alg : new String[] {"AESWRAP", "AESWRAPPAD"}) {
                Cipher c = Cipher.getInstance(alg, BC);
                c.init(Cipher.WRAP_MODE, kek);
                byte[] wrapped = c.wrap(new SecretKeySpec(random(32), "AES"));
                info(alg, shortHex(wrapped));
            }
        });
        step("RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING (BC naming)", () -> {
            KeyPair kp = KeyPairGenerator.getInstance("RSA", BC).generateKeyPair();
            Cipher enc = Cipher.getInstance("RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING", BC);
            enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] ct = enc.doFinal(MSG);
            Cipher dec = Cipher.getInstance("RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING", BC);
            dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            require(Arrays.equals(MSG, dec.doFinal(ct)), "round trip failed");
        });
        step("ElGamal/NONE/PKCS1Padding", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ElGamal", BC);
            kpg.initialize(512);
            KeyPair kp = kpg.generateKeyPair();
            byte[] small = Arrays.copyOf(MSG, 16);
            Cipher enc = Cipher.getInstance("ElGamal/NONE/PKCS1Padding", BC);
            enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] ct = enc.doFinal(small);
            Cipher dec = Cipher.getInstance("ElGamal/NONE/PKCS1Padding", BC);
            dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            require(Arrays.equals(small, dec.doFinal(ct)), "round trip failed");
        });
    }

    private static void pbe() {
        section("Password-based encryption and key derivation");
        char[] password = "correct horse".toCharArray();
        byte[] salt = random(16);
        for (String alg : List.of("PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA3-256",
                "PBKDF2WithHmacSHA512", "PBKDF2WithHmacSM3", "PBKDF2WithHmacGOST3411")) {
            step(alg, () -> {
                SecretKey key = SecretKeyFactory.getInstance(alg, BC).generateSecret(new PBEKeySpec(password, salt, 10_000, 256));
                info(alg, shortHex(key.getEncoded()));
            });
        }
        step("SCRYPT SecretKeyFactory (ScryptKeySpec)", () -> {
            SecretKey key = SecretKeyFactory.getInstance("SCRYPT", BC)
                    .generateSecret(new ScryptKeySpec(password, salt, 1 << 14, 8, 1, 256));
            info("SCRYPT", shortHex(key.getEncoded()));
        });
        step("PBEWITHSHA256AND256BITAES-CBC-BC encryption", () -> {
            SecretKey key = SecretKeyFactory.getInstance("PBEWITHSHA256AND256BITAES-CBC-BC", BC)
                    .generateSecret(new PBEKeySpec(password));
            PBEParameterSpec spec = new PBEParameterSpec(salt, 10_000);
            Cipher enc = Cipher.getInstance("PBEWITHSHA256AND256BITAES-CBC-BC", BC);
            enc.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] ct = enc.doFinal(MSG);
            Cipher dec = Cipher.getInstance("PBEWITHSHA256AND256BITAES-CBC-BC", BC);
            dec.init(Cipher.DECRYPT_MODE, key, spec);
            require(Arrays.equals(MSG, dec.doFinal(ct)), "round trip failed");
        });
        step("PBEWITHSHAAND3-KEYTRIPLEDES-CBC (PKCS#12 PBE)", () -> {
            SecretKey key = SecretKeyFactory.getInstance("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", BC)
                    .generateSecret(new PBEKeySpec(password));
            PBEParameterSpec spec = new PBEParameterSpec(salt, 10_000);
            Cipher enc = Cipher.getInstance("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", BC);
            enc.init(Cipher.ENCRYPT_MODE, key, spec);
            Cipher dec = Cipher.getInstance("PBEWITHSHAAND3-KEYTRIPLEDES-CBC", BC);
            dec.init(Cipher.DECRYPT_MODE, key, spec);
            require(Arrays.equals(MSG, dec.doFinal(enc.doFinal(MSG))), "round trip failed");
        });
    }

    private static void signatures() {
        section("KeyPairGenerator and Signature");
        step("ECDSA (secp256r1, secp256k1, brainpoolP256r1, brainpoolP384r1, sm2p256v1)", () -> {
            for (String curve : new String[] {"secp256r1", "secp256k1", "brainpoolP256r1", "brainpoolP384r1"}) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BC);
                kpg.initialize(new ECGenParameterSpec(curve));
                signVerify("SHA256withECDSA", kpg.generateKeyPair(), curve);
            }
        });
        step("ECDSA variants: SHA3-256withECDSA, SHA256withPLAIN-ECDSA, RIPEMD160withECDSA, SHA256withCVC-ECDSA", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BC);
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            for (String alg : new String[] {"SHA3-256withECDSA", "SHA256withPLAIN-ECDSA", "RIPEMD160withECDSA",
                    "SHA256withCVC-ECDSA"}) {
                signVerify(alg, kp, alg);
            }
        });
        step("SM3withSM2", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
            kpg.initialize(new ECGenParameterSpec("sm2p256v1"));
            signVerify("SM3withSM2", kpg.generateKeyPair(), "sm2p256v1");
        });
        step("RSA: SHA256withRSA, SHA3-256withRSA, RIPEMD160withRSA, SHA256withRSA/ISO9796-2, SHA256withRSAandMGF1", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
            kpg.initialize(3072);
            KeyPair kp = kpg.generateKeyPair();
            for (String alg : new String[] {"SHA256withRSA", "SHA3-256withRSA", "RIPEMD160withRSA",
                    "SHA256withRSAandMGF1", "SHA256withRSA/ISO9796-2", "SHA256withRSA/X9.31"}) {
                signVerify(alg, kp, alg);
            }
        });
        step("RSASSA-PSS with PSSParameterSpec", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
            kpg.initialize(3072);
            KeyPair kp = kpg.generateKeyPair();
            Signature s = Signature.getInstance("RSASSA-PSS", BC);
            s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            s.initSign(kp.getPrivate());
            s.update(MSG);
            byte[] sig = s.sign();
            Signature v = Signature.getInstance("RSASSA-PSS", BC);
            v.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            v.initVerify(kp.getPublic());
            v.update(MSG);
            require(v.verify(sig), "verification failed");
        });
        for (String alg : new String[] {"Ed25519", "Ed448"}) {
            step(alg, () -> signVerify(alg, KeyPairGenerator.getInstance(alg, BC).generateKeyPair(), alg));
        }
        step("DSA (SHA256withDSA)", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", BC);
            kpg.initialize(2048);
            signVerify("SHA256withDSA", kpg.generateKeyPair(), "DSA-2048");
        });
        step("ECGOST3410-2012 (Tc26-Gost-3410-12-256-paramSetA)", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECGOST3410-2012", BC);
            kpg.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-256-paramSetA"));
            signVerify("GOST3411-2012-256WITHECGOST3410-2012-256", kpg.generateKeyPair(), "GOST R 34.10-2012");
        });
        step("DSTU4145 (Ukrainian standard)", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSTU4145", BC);
            kpg.initialize(new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2.0"));
            signVerify("GOST3411withDSTU4145", kpg.generateKeyPair(), "DSTU 4145");
        });
        step("EC key pair parameters round trip (AlgorithmParameters \"EC\")", () -> {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", BC);
            params.init(new ECGenParameterSpec("secp384r1"));
            info("DER", shortHex(params.getEncoded()));
        });
    }

    private static void signVerify(String algorithm, KeyPair kp, String label) throws Exception {
        Signature signer = Signature.getInstance(algorithm, BC);
        signer.initSign(kp.getPrivate());
        signer.update(MSG);
        byte[] sig = signer.sign();
        Signature verifier = Signature.getInstance(algorithm, BC);
        verifier.initVerify(kp.getPublic());
        verifier.update(MSG);
        require(verifier.verify(sig), label + ": signature did not verify");
        info(label + " [" + algorithm + "]", shortHex(sig));
    }

    private static void keyAgreement() {
        section("KeyAgreement");
        step("ECDH and ECDHC (secp256r1)", () -> {
            for (String alg : new String[] {"ECDH", "ECDHC"}) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
                kpg.initialize(new ECGenParameterSpec("secp256r1"));
                KeyPair a = kpg.generateKeyPair();
                KeyPair b = kpg.generateKeyPair();
                info(alg, shortHex(agree(alg, a, b, null)));
            }
        });
        step("ECDHwithSHA256KDF (X9.63 KDF with user keying material)", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair a = kpg.generateKeyPair();
            KeyPair b = kpg.generateKeyPair();
            UserKeyingMaterialSpec ukm = new UserKeyingMaterialSpec(random(16));
            KeyAgreement ka = KeyAgreement.getInstance("ECDHwithSHA256KDF", BC);
            ka.init(a.getPrivate(), ukm);
            ka.doPhase(b.getPublic(), true);
            SecretKey key = ka.generateSecret("AES[256]");
            info("derived AES-256 key", shortHex(key.getEncoded()));
        });
        for (String alg : new String[] {"X25519", "X448"}) {
            step(alg, () -> {
                KeyPair a = KeyPairGenerator.getInstance(alg, BC).generateKeyPair();
                KeyPair b = KeyPairGenerator.getInstance(alg, BC).generateKeyPair();
                info(alg, shortHex(agree(alg, a, b, null)));
            });
        }
        step("DH 2048-bit", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", BC);
            kpg.initialize(2048);
            KeyPair a = kpg.generateKeyPair();
            KeyPair b = kpg.generateKeyPair();
            info("DH", shortHex(agree("DH", a, b, null)));
        });
    }

    private static byte[] agree(String alg, KeyPair a, KeyPair b, java.security.spec.AlgorithmParameterSpec spec)
            throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(alg, BC);
        ka.init(a.getPrivate());
        ka.doPhase(b.getPublic(), true);
        byte[] s1 = ka.generateSecret();
        KeyAgreement kb = KeyAgreement.getInstance(alg, BC);
        kb.init(b.getPrivate());
        kb.doPhase(a.getPublic(), true);
        require(Arrays.equals(s1, kb.generateSecret()), alg + ": shared secrets differ");
        return s1;
    }

    private static void ecies() {
        section("Integrated encryption schemes");
        step("ECIES (ECIESwithAES-CBC, IESParameterSpec)", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = kpg.generateKeyPair();
            IESParameterSpec spec = new IESParameterSpec(random(16), random(16), 256, 128, random(16));
            Cipher enc = Cipher.getInstance("ECIESwithAES-CBC", BC);
            enc.init(Cipher.ENCRYPT_MODE, kp.getPublic(), spec);
            byte[] ct = enc.doFinal(MSG);
            Cipher dec = Cipher.getInstance("ECIESwithAES-CBC", BC);
            dec.init(Cipher.DECRYPT_MODE, kp.getPrivate(), spec);
            require(Arrays.equals(MSG, dec.doFinal(ct)), "round trip failed");
            info("ciphertext", shortHex(ct));
        });
        step("SM2 cipher", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BC);
            kpg.initialize(new ECGenParameterSpec("sm2p256v1"));
            KeyPair kp = kpg.generateKeyPair();
            Cipher enc = Cipher.getInstance("SM2", BC);
            enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] ct = enc.doFinal(MSG);
            Cipher dec = Cipher.getInstance("SM2", BC);
            dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            require(Arrays.equals(MSG, dec.doFinal(ct)), "round trip failed");
        });
    }
}
