package cryptodemo.bouncycastle;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.ARIAEngine;
import org.bouncycastle.crypto.engines.AsconAEAD128;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.engines.Grain128AEADEngine;
import org.bouncycastle.crypto.engines.Grain128Engine;
import org.bouncycastle.crypto.engines.Grainv1Engine;
import org.bouncycastle.crypto.engines.HC128Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.engines.IDEAEngine;
import org.bouncycastle.crypto.engines.ISAACEngine;
import org.bouncycastle.crypto.engines.NoekeonEngine;
import org.bouncycastle.crypto.engines.PhotonBeetleEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.RC532Engine;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.engines.RFC5649WrapEngine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.engines.Shacal2Engine;
import org.bouncycastle.crypto.engines.TEAEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.engines.VMPCEngine;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.crypto.engines.XTEAEngine;
import org.bouncycastle.crypto.engines.XoodyakEngine;
import org.bouncycastle.crypto.engines.Zuc128Engine;
import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.fpe.FPEFF3_1Engine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMSIVBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.X923Padding;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/** BouncyCastle lightweight API: block ciphers, modes, padding, stream ciphers, AEAD, key wrap and format-preserving encryption. */
public final class BcSymmetricDemo {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] PLAINTEXT =
            "Sensitive data that needs protecting - 0123456789".getBytes(StandardCharsets.UTF_8);
    private static final byte[] AAD = "header-v1".getBytes(StandardCharsets.UTF_8);

    private BcSymmetricDemo() {
    }

    public static void run() {
        blockCiphers();
        modesAndPadding();
        streamCiphers();
        aeadModes();
        aeadStreamCiphers();
        keyWrap();
        formatPreserving();
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private record Block(String name, Supplier<BlockCipher> engine, int keyBytes) {
    }

    private static void blockCiphers() {
        section("Block ciphers (CBC + PKCS7)");
        List<Block> ciphers = List.of(
                new Block("AES-256", AESEngine::newInstance, 32),
                new Block("Twofish-256", TwofishEngine::new, 32),
                new Block("Serpent-256", SerpentEngine::new, 32),
                new Block("Camellia-256", CamelliaEngine::new, 32),
                new Block("ARIA-256", ARIAEngine::new, 32),
                new Block("SM4", SM4Engine::new, 16),
                new Block("SEED", SEEDEngine::new, 16),
                new Block("CAST6-256", CAST6Engine::new, 32),
                new Block("RC6-256", RC6Engine::new, 32),
                new Block("Noekeon", NoekeonEngine::new, 16),
                new Block("DSTU7624-128", () -> new DSTU7624Engine(128), 16),
                new Block("Shacal2", Shacal2Engine::new, 32),
                new Block("3DES", DESedeEngine::new, 24),
                new Block("DES (broken)", DESEngine::new, 8),
                new Block("Blowfish", BlowfishEngine::new, 16),
                new Block("CAST5", CAST5Engine::new, 16),
                new Block("IDEA", IDEAEngine::new, 16),
                new Block("RC2", RC2Engine::new, 16),
                new Block("RC5-32", RC532Engine::new, 16),
                new Block("GOST 28147-89", GOST28147Engine::new, 32),
                new Block("TEA", TEAEngine::new, 16),
                new Block("XTEA", XTEAEngine::new, 16));
        for (Block c : ciphers) {
            step(c.name(), () -> {
                byte[] key = random(c.keyBytes());
                int blockSize = c.engine().get().getBlockSize();
                CipherParameters params = new ParametersWithIV(new KeyParameter(key), random(blockSize));

                byte[] ct = process(new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(c.engine().get()), new PKCS7Padding()),
                        true, params, PLAINTEXT);
                byte[] pt = process(new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(c.engine().get()), new PKCS7Padding()),
                        false, params, ct);
                require(Arrays.equals(PLAINTEXT, pt), "round trip failed");
                info(c.name() + " (block " + blockSize * 8 + " bits)", shortHex(ct));
            });
        }
    }

    private static void modesAndPadding() {
        section("Modes of operation (AES-256) and padding schemes");
        byte[] key = random(32);
        byte[] iv = random(16);
        CipherParameters ivParams = new ParametersWithIV(new KeyParameter(key), iv);

        step("CBC + PKCS7", () -> roundTrip(
                () -> new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()), new PKCS7Padding()), ivParams));
        step("CBC + ISO 10126-2", () -> roundTrip(
                () -> new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()), new ISO10126d2Padding()), ivParams));
        step("CBC + ISO 7816-4", () -> roundTrip(
                () -> new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()), new ISO7816d4Padding()), ivParams));
        step("CBC + ANSI X9.23", () -> roundTrip(
                () -> new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()), new X923Padding()), ivParams));
        step("CBC + zero-byte padding", () -> roundTrip(
                () -> new PaddedBufferedBlockCipher(CBCBlockCipher.newInstance(AESEngine.newInstance()), new ZeroBytePadding()), ivParams));
        step("CTR (SICBlockCipher)", () -> roundTrip(
                () -> new DefaultBufferedBlockCipher(SICBlockCipher.newInstance(AESEngine.newInstance())), ivParams));
        step("CFB-128", () -> roundTrip(
                () -> new DefaultBufferedBlockCipher(CFBBlockCipher.newInstance(AESEngine.newInstance(), 128)), ivParams));
        step("CFB-8", () -> roundTrip(
                () -> new DefaultBufferedBlockCipher(CFBBlockCipher.newInstance(AESEngine.newInstance(), 8)), ivParams));
        step("OFB-128", () -> roundTrip(
                () -> new DefaultBufferedBlockCipher(new OFBBlockCipher(AESEngine.newInstance(), 128)), ivParams));
        step("ECB (insecure, no IV)", () -> roundTrip(
                () -> new PaddedBufferedBlockCipher(AESEngine.newInstance(), new PKCS7Padding()), new KeyParameter(key)));
    }

    private static void roundTrip(Supplier<BufferedBlockCipher> cipher, CipherParameters params) throws Exception {
        byte[] ct = process(cipher.get(), true, params, PLAINTEXT);
        byte[] pt = process(cipher.get(), false, params, ct);
        // Zero-byte padding strips trailing zeros only, so the plaintext must not end in one
        require(Arrays.equals(PLAINTEXT, pt), "round trip failed");
        info("ciphertext", shortHex(ct));
    }

    private static byte[] process(BufferedBlockCipher cipher, boolean encrypt, CipherParameters params, byte[] input)
            throws Exception {
        cipher.init(encrypt, params);
        byte[] out = new byte[cipher.getOutputSize(input.length)];
        int n = cipher.processBytes(input, 0, input.length, out, 0);
        n += cipher.doFinal(out, n);
        return Arrays.copyOf(out, n);
    }

    private record Stream(String name, Supplier<StreamCipher> engine, int keyBytes, int ivBytes) {
    }

    private static void streamCiphers() {
        section("Stream ciphers");
        List<Stream> ciphers = List.of(
                new Stream("ChaCha20 (RFC 7539, 96-bit nonce)", ChaCha7539Engine::new, 32, 12),
                new Stream("ChaCha (original, 64-bit nonce)", ChaChaEngine::new, 32, 8),
                new Stream("Salsa20", Salsa20Engine::new, 32, 8),
                new Stream("XSalsa20", XSalsa20Engine::new, 32, 24),
                new Stream("HC-128", HC128Engine::new, 16, 16),
                new Stream("HC-256", HC256Engine::new, 32, 32),
                new Stream("Grain v1", Grainv1Engine::new, 10, 8),
                new Stream("Grain-128", Grain128Engine::new, 16, 12),
                new Stream("ZUC-128", Zuc128Engine::new, 16, 16),
                new Stream("VMPC", VMPCEngine::new, 16, 16),
                new Stream("RC4 (broken)", RC4Engine::new, 16, 0),
                new Stream("ISAAC", ISAACEngine::new, 16, 0));
        for (Stream s : ciphers) {
            step(s.name(), () -> {
                KeyParameter key = new KeyParameter(random(s.keyBytes()));
                CipherParameters params = s.ivBytes() == 0 ? key : new ParametersWithIV(key, random(s.ivBytes()));

                StreamCipher enc = s.engine().get();
                enc.init(true, params);
                byte[] ct = new byte[PLAINTEXT.length];
                enc.processBytes(PLAINTEXT, 0, PLAINTEXT.length, ct, 0);

                StreamCipher dec = s.engine().get();
                dec.init(false, params);
                byte[] pt = new byte[ct.length];
                dec.processBytes(ct, 0, ct.length, pt, 0);
                require(Arrays.equals(PLAINTEXT, pt), "round trip failed");
                info(s.name(), shortHex(ct));
            });
        }
    }

    private static void aeadModes() {
        section("Authenticated encryption (AEAD)");
        byte[] key = random(32);

        step("AES-GCM (128-bit tag)", () -> aead(GCMBlockCipher.newInstance(AESEngine.newInstance()),
                GCMBlockCipher.newInstance(AESEngine.newInstance()), new AEADParameters(new KeyParameter(key), 128, random(12), AAD)));
        step("AES-GCM-SIV (RFC 8452, nonce-misuse resistant)", () -> aead(new GCMSIVBlockCipher(AESEngine.newInstance()),
                new GCMSIVBlockCipher(AESEngine.newInstance()), new AEADParameters(new KeyParameter(key), 128, random(12), AAD)));
        step("AES-CCM", () -> aead(CCMBlockCipher.newInstance(AESEngine.newInstance()),
                CCMBlockCipher.newInstance(AESEngine.newInstance()), new AEADParameters(new KeyParameter(key), 128, random(12), AAD)));
        step("AES-EAX", () -> aead(new EAXBlockCipher(AESEngine.newInstance()),
                new EAXBlockCipher(AESEngine.newInstance()), new AEADParameters(new KeyParameter(key), 128, random(16), AAD)));
        step("AES-OCB", () -> aead(new OCBBlockCipher(AESEngine.newInstance(), AESEngine.newInstance()),
                new OCBBlockCipher(AESEngine.newInstance(), AESEngine.newInstance()),
                new AEADParameters(new KeyParameter(key), 128, random(12), AAD)));
        step("Twofish-GCM", () -> aead(GCMBlockCipher.newInstance(new TwofishEngine()),
                GCMBlockCipher.newInstance(new TwofishEngine()), new AEADParameters(new KeyParameter(key), 128, random(12), AAD)));
        step("ChaCha20-Poly1305 (RFC 8439)", () -> aead(new ChaCha20Poly1305(), new ChaCha20Poly1305(),
                new ParametersWithIV(new KeyParameter(key), random(12))));
        step("GCM tamper detection (InvalidCipherTextException)", () -> {
            AEADParameters params = new AEADParameters(new KeyParameter(key), 128, random(12), AAD);
            AEADBlockCipher enc = GCMBlockCipher.newInstance(AESEngine.newInstance());
            enc.init(true, params);
            byte[] ct = new byte[enc.getOutputSize(PLAINTEXT.length)];
            int n = enc.processBytes(PLAINTEXT, 0, PLAINTEXT.length, ct, 0);
            enc.doFinal(ct, n);
            ct[0] ^= 1;

            AEADBlockCipher dec = GCMBlockCipher.newInstance(AESEngine.newInstance());
            dec.init(false, params);
            byte[] out = new byte[dec.getOutputSize(ct.length)];
            try {
                int m = dec.processBytes(ct, 0, ct.length, out, 0);
                dec.doFinal(out, m);
                throw new IllegalStateException("tampering was not detected");
            } catch (org.bouncycastle.crypto.InvalidCipherTextException expected) {
                info("result", "rejected as expected");
            }
        });
    }

    private static void aeadStreamCiphers() {
        section("NIST lightweight-cryptography AEAD (Ascon, Xoodyak, Photon-Beetle, Grain-128AEAD)");
        step("Ascon-AEAD128", () -> aead(new AsconAEAD128(), new AsconAEAD128(),
                new ParametersWithIV(new KeyParameter(random(16)), random(16))));
        step("Xoodyak", () -> aead(new XoodyakEngine(), new XoodyakEngine(),
                new ParametersWithIV(new KeyParameter(random(16)), random(16))));
        step("Photon-Beetle", () -> aead(
                new PhotonBeetleEngine(PhotonBeetleEngine.PhotonBeetleParameters.pb128),
                new PhotonBeetleEngine(PhotonBeetleEngine.PhotonBeetleParameters.pb128),
                new ParametersWithIV(new KeyParameter(random(16)), random(16))));
        step("Grain-128AEAD", () -> aead(new Grain128AEADEngine(), new Grain128AEADEngine(),
                new ParametersWithIV(new KeyParameter(random(16)), random(12))));
    }

    private static void aead(AEADCipher enc, AEADCipher dec, CipherParameters params) throws Exception {
        enc.init(true, params);
        enc.processAADBytes(AAD, 0, AAD.length);
        byte[] ct = new byte[enc.getOutputSize(PLAINTEXT.length)];
        int n = enc.processBytes(PLAINTEXT, 0, PLAINTEXT.length, ct, 0);
        n += enc.doFinal(ct, n);

        dec.init(false, params);
        dec.processAADBytes(AAD, 0, AAD.length);
        byte[] pt = new byte[dec.getOutputSize(n)];
        int m = dec.processBytes(ct, 0, n, pt, 0);
        m += dec.doFinal(pt, m);
        require(Arrays.equals(PLAINTEXT, Arrays.copyOf(pt, m)), "round trip failed");
        info("ciphertext+tag (" + enc.getAlgorithmName() + ")", shortHex(Arrays.copyOf(ct, n)));
    }

    private static void keyWrap() {
        section("Key wrapping");
        byte[] kek = random(32);
        byte[] cek = random(32);
        step("RFC 3394 AES key wrap", () -> wrap(new RFC3394WrapEngine(AESEngine.newInstance()), kek, cek));
        step("RFC 5649 AES key wrap with padding (arbitrary length)", () -> wrap(
                new RFC5649WrapEngine(AESEngine.newInstance()), kek, random(20)));
    }

    private static void wrap(Wrapper w, byte[] kek, byte[] cek) throws Exception {
        w.init(true, new KeyParameter(kek));
        byte[] wrapped = w.wrap(cek, 0, cek.length);
        w.init(false, new KeyParameter(kek));
        byte[] unwrapped = w.unwrap(wrapped, 0, wrapped.length);
        require(Arrays.equals(cek, unwrapped), "unwrap mismatch");
        info(w.getAlgorithmName(), shortHex(wrapped));
    }

    private static void formatPreserving() {
        section("Format-preserving encryption (NIST SP 800-38G)");
        byte[] key = random(16);
        step("FF1 radix 10 (e.g. 16-digit card number)", () -> {
            String card = "4111111111111111";
            byte[] digits = new byte[card.length()];
            for (int i = 0; i < digits.length; i++) {
                digits[i] = (byte) (card.charAt(i) - '0');
            }
            FPEFF1Engine enc = new FPEFF1Engine();
            enc.init(true, new FPEParameters(new KeyParameter(key), 10, "tweak".getBytes(StandardCharsets.UTF_8)));
            byte[] ct = new byte[digits.length];
            enc.processBlock(digits, 0, digits.length, ct, 0);
            FPEFF1Engine dec = new FPEFF1Engine();
            dec.init(false, new FPEParameters(new KeyParameter(key), 10, "tweak".getBytes(StandardCharsets.UTF_8)));
            byte[] pt = new byte[ct.length];
            dec.processBlock(ct, 0, ct.length, pt, 0);
            require(Arrays.equals(digits, pt), "round trip failed");
            StringBuilder sb = new StringBuilder();
            for (byte b : ct) {
                sb.append((char) ('0' + b));
            }
            info("4111111111111111 ->", sb);
        });
        step("FF3-1 radix 10", () -> {
            byte[] digits = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
            byte[] tweak = new byte[7];
            FPEFF3_1Engine enc = new FPEFF3_1Engine();
            enc.init(true, new FPEParameters(new KeyParameter(key), 10, tweak));
            byte[] ct = new byte[digits.length];
            enc.processBlock(digits, 0, digits.length, ct, 0);
            FPEFF3_1Engine dec = new FPEFF3_1Engine();
            dec.init(false, new FPEParameters(new KeyParameter(key), 10, tweak));
            byte[] pt = new byte[ct.length];
            dec.processBlock(ct, 0, ct.length, pt, 0);
            require(Arrays.equals(digits, pt), "round trip failed");
            info("ciphertext digits", Arrays.toString(ct));
        });
    }
}
