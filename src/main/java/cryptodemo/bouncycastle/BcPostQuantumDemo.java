package cryptodemo.bouncycastle;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.function.Function;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.CMCEKeyPairGenerator;
import org.bouncycastle.crypto.generators.FrodoKEMKeyPairGenerator;
import org.bouncycastle.crypto.generators.LMSKeyPairGenerator;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.generators.SLHDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.XMSSKeyPairGenerator;
import org.bouncycastle.crypto.kems.CMCEKEMExtractor;
import org.bouncycastle.crypto.kems.CMCEKEMGenerator;
import org.bouncycastle.crypto.kems.FrodoKEMExtractor;
import org.bouncycastle.crypto.kems.FrodoKEMGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.CMCEKeyGenerationParameters;
import org.bouncycastle.crypto.params.CMCEParameters;
import org.bouncycastle.crypto.params.CMCEPrivateKeyParameters;
import org.bouncycastle.crypto.params.FrodoKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.FrodoKEMParameters;
import org.bouncycastle.crypto.params.FrodoKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.XMSSKeyGenerationParameters;
import org.bouncycastle.crypto.params.XMSSParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.signers.SLHDSASigner;
import org.bouncycastle.crypto.signers.XMSSSigner;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMExtractor;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;

/** BouncyCastle post-quantum cryptography: KEMs and signatures (lightweight API and provider API). */
public final class BcPostQuantumDemo {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] MSG = "document to be signed".getBytes(StandardCharsets.UTF_8);

    private BcPostQuantumDemo() {
    }

    public static void run() {
        kems();
        signatures();
        statefulHashSignatures();
        providerApi();
    }

    private static void kem(String name, AsymmetricCipherKeyPairGenerator gen, KeyGenerationParameters params,
            EncapsulatedSecretGenerator generator,
            Function<AsymmetricKeyParameter, EncapsulatedSecretExtractor> extractor) {
        step(name, () -> {
            gen.init(params);
            AsymmetricCipherKeyPair kp = gen.generateKeyPair();
            SecretWithEncapsulation sent = generator.generateEncapsulated(kp.getPublic());
            byte[] received = extractor.apply(kp.getPrivate()).extractSecret(sent.getEncapsulation());
            require(Arrays.equals(sent.getSecret(), received), "shared secrets differ");
            info(name, "ciphertext " + sent.getEncapsulation().length + " bytes, secret " + shortHex(received));
        });
    }

    private static void kems() {
        section("Key encapsulation mechanisms (lightweight API)");
        for (MLKEMParameters p : new MLKEMParameters[] {MLKEMParameters.ml_kem_512, MLKEMParameters.ml_kem_768,
                MLKEMParameters.ml_kem_1024}) {
            kem(p.getName() + " (FIPS 203)", new MLKEMKeyPairGenerator(), new MLKEMKeyGenerationParameters(RANDOM, p),
                    new MLKEMGenerator(RANDOM), k -> new MLKEMExtractor((MLKEMPrivateKeyParameters) k));
        }
        for (FrodoKEMParameters p : new FrodoKEMParameters[] {FrodoKEMParameters.frodokem976aes,
                FrodoKEMParameters.frodokem976shake, FrodoKEMParameters.frodokem1344aes}) {
            kem("FrodoKEM " + p.getName(), new FrodoKEMKeyPairGenerator(), new FrodoKEMKeyGenerationParameters(RANDOM, p),
                    new FrodoKEMGenerator(RANDOM), k -> new FrodoKEMExtractor((FrodoKEMPrivateKeyParameters) k));
        }
        for (NTRUParameters p : new NTRUParameters[] {NTRUParameters.ntruhps2048509, NTRUParameters.ntruhrss701}) {
            kem("NTRU " + p.getName(), new NTRUKeyPairGenerator(), new NTRUKeyGenerationParameters(RANDOM, p),
                    new NTRUKEMGenerator(RANDOM), k -> new NTRUKEMExtractor((NTRUPrivateKeyParameters) k));
        }
        kem("NTRU LPRime ntrulpr653", new NTRULPRimeKeyPairGenerator(),
                new NTRULPRimeKeyGenerationParameters(RANDOM, NTRULPRimeParameters.ntrulpr653),
                new NTRULPRimeKEMGenerator(RANDOM), k -> new NTRULPRimeKEMExtractor((NTRULPRimePrivateKeyParameters) k));
        kem("Streamlined NTRU Prime sntrup653", new SNTRUPrimeKeyPairGenerator(),
                new SNTRUPrimeKeyGenerationParameters(RANDOM, SNTRUPrimeParameters.sntrup653),
                new SNTRUPrimeKEMGenerator(RANDOM), k -> new SNTRUPrimeKEMExtractor((SNTRUPrimePrivateKeyParameters) k));
        for (HQCParameters p : new HQCParameters[] {HQCParameters.hqc128, HQCParameters.hqc192, HQCParameters.hqc256}) {
            kem("HQC " + p.getName(), new HQCKeyPairGenerator(), new HQCKeyGenerationParameters(RANDOM, p),
                    new HQCKEMGenerator(RANDOM), k -> new HQCKEMExtractor((HQCPrivateKeyParameters) k));
        }
        kem("Classic McEliece " + CMCEParameters.mceliece460896.getName(), new CMCEKeyPairGenerator(),
                new CMCEKeyGenerationParameters(RANDOM, CMCEParameters.mceliece460896),
                new CMCEKEMGenerator(RANDOM), k -> new CMCEKEMExtractor((CMCEPrivateKeyParameters) k));
    }

    private static void signMessage(String name, AsymmetricCipherKeyPairGenerator gen, KeyGenerationParameters params,
            MessageSigner signer) {
        step(name, () -> {
            gen.init(params);
            AsymmetricCipherKeyPair kp = gen.generateKeyPair();
            signer.init(true, new ParametersWithRandom(kp.getPrivate(), RANDOM));
            byte[] sig = signer.generateSignature(MSG);
            signer.init(false, kp.getPublic());
            require(signer.verifySignature(MSG, sig), "signature did not verify");
            byte[] tampered = MSG.clone();
            tampered[0] ^= 1;
            require(!signer.verifySignature(tampered, sig), "tampered message verified");
            info(name, "signature " + sig.length + " bytes");
        });
    }

    private static void signatures() {
        section("Stateless signatures (lightweight API)");
        for (MLDSAParameters p : new MLDSAParameters[] {MLDSAParameters.ml_dsa_44, MLDSAParameters.ml_dsa_65,
                MLDSAParameters.ml_dsa_87}) {
            step(p.getName() + " (FIPS 204)", () -> {
                MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
                gen.init(new MLDSAKeyGenerationParameters(RANDOM, p));
                AsymmetricCipherKeyPair kp = gen.generateKeyPair();
                Signer signer = new MLDSASigner();
                signer.init(true, new ParametersWithRandom(kp.getPrivate(), RANDOM));
                signer.update(MSG, 0, MSG.length);
                byte[] sig = signer.generateSignature();
                signer.init(false, kp.getPublic());
                signer.update(MSG, 0, MSG.length);
                require(signer.verifySignature(sig), "signature did not verify");
                info(p.getName(), "signature " + sig.length + " bytes");
            });
        }
        for (SLHDSAParameters p : new SLHDSAParameters[] {SLHDSAParameters.sha2_128f,
                SLHDSAParameters.shake_128f, SLHDSAParameters.sha2_192f, SLHDSAParameters.sha2_256f}) {
            step(p.getName() + " (FIPS 205)", () -> {
                SLHDSAKeyPairGenerator gen = new SLHDSAKeyPairGenerator();
                gen.init(new SLHDSAKeyGenerationParameters(RANDOM, p));
                AsymmetricCipherKeyPair kp = gen.generateKeyPair();
                SLHDSASigner signer = new SLHDSASigner();
                signer.init(true, new ParametersWithRandom(kp.getPrivate(), RANDOM));
                byte[] sig = signer.generateSignature(MSG);
                signer.init(false, kp.getPublic());
                require(signer.verifySignature(MSG, sig), "signature did not verify");
                info(p.getName(), "signature " + sig.length + " bytes");
            });
        }
        for (FalconParameters p : new FalconParameters[] {FalconParameters.falcon_512, FalconParameters.falcon_1024}) {
            signMessage(p.getName() + " (FN-DSA draft)", new FalconKeyPairGenerator(),
                    new FalconKeyGenerationParameters(RANDOM, p), new FalconSigner());
        }
    }

    private static void statefulHashSignatures() {
        section("Stateful hash-based signatures (NIST SP 800-208)");
        step("XMSS (SHA-256, height 4)", () -> {
            XMSSKeyPairGenerator gen = new XMSSKeyPairGenerator();
            gen.init(new XMSSKeyGenerationParameters(new XMSSParameters(4, new SHA256Digest()), RANDOM));
            AsymmetricCipherKeyPair kp = gen.generateKeyPair();
            XMSSSigner signer = new XMSSSigner();
            signer.init(true, kp.getPrivate());
            signer.update(MSG, 0, MSG.length);
            byte[] sig = signer.generateSignature();
            signer.init(false, kp.getPublic());
            signer.update(MSG, 0, MSG.length);
            require(signer.verifySignature(sig), "signature did not verify");
            info("XMSS", "signature " + sig.length + " bytes");
        });
        step("LMS (SHA-256, height 5, Winternitz 4)", () -> {
            LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
            gen.init(new LMSKeyGenerationParameters(
                    new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4), RANDOM));
            AsymmetricCipherKeyPair kp = gen.generateKeyPair();
            org.bouncycastle.crypto.signers.LMSSigner signer = new org.bouncycastle.crypto.signers.LMSSigner();
            signer.init(true, kp.getPrivate());
            byte[] sig = signer.generateSignature(MSG);
            signer.init(false, kp.getPublic());
            require(signer.verifySignature(MSG, sig), "signature did not verify");
            info("LMS", "signature " + sig.length + " bytes");
        });
    }

    private static void providerApi() {
        section("Provider API (KeyPairGenerator / Signature / KeyGenerator with \"BC\")");
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        for (String alg : new String[] {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F",
                "SLH-DSA-SHAKE-128F", "Falcon-512", "Falcon-1024"}) {
            step(alg + " via Signature", () -> {
                KeyPair kp = KeyPairGenerator.getInstance(alg, "BC").generateKeyPair();
                Signature signer = Signature.getInstance(alg, "BC");
                signer.initSign(kp.getPrivate());
                signer.update(MSG);
                byte[] sig = signer.sign();
                Signature verifier = Signature.getInstance(alg, "BC");
                verifier.initVerify(kp.getPublic());
                verifier.update(MSG);
                require(verifier.verify(sig), "signature did not verify");
                info(alg, "signature " + sig.length + " bytes");
            });
        }
        for (String alg : new String[] {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
            step(alg + " via KeyGenerator with KEMGenerateSpec / KEMExtractSpec", () -> {
                KeyPair kp = KeyPairGenerator.getInstance(alg, "BC").generateKeyPair();

                KeyGenerator sender = KeyGenerator.getInstance(alg, "BC");
                sender.init(new KEMGenerateSpec(kp.getPublic(), "AES"), RANDOM);
                SecretKeyWithEncapsulation sent = (SecretKeyWithEncapsulation) sender.generateKey();

                KeyGenerator receiver = KeyGenerator.getInstance(alg, "BC");
                receiver.init(new KEMExtractSpec(kp.getPrivate(), sent.getEncapsulation(), "AES"));
                SecretKey received = receiver.generateKey();
                require(Arrays.equals(sent.getEncoded(), received.getEncoded()), "shared secrets differ");
                info(alg, "ciphertext " + sent.getEncapsulation().length + " bytes");
            });
        }
    }
}
