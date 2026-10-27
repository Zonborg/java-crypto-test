package cryptodemo.bouncycastle;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import java.util.function.Supplier;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.Blake2bDigest;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.crypto.digests.DSTU7564Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_512Digest;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.ParallelHash;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.crypto.digests.RIPEMD320Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.digests.SkeinDigest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.digests.TupleHash;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.macs.SipHash;
import org.bouncycastle.crypto.macs.SkeinMac;
import org.bouncycastle.crypto.macs.VMPCMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/** BouncyCastle lightweight API (org.bouncycastle.crypto): message digests, XOFs and MACs. */
public final class BcDigestMacDemo {

    private static final byte[] MSG = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RANDOM = new SecureRandom();

    private BcDigestMacDemo() {
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    public static void run() {
        digests();
        xofs();
        macs();
    }

    private static void digests() {
        section("Message digests");
        List<Supplier<Digest>> digests = List.of(
                MD2Digest::new, MD4Digest::new, MD5Digest::new, SHA1Digest::new,
                SHA224Digest::new, SHA256Digest::new, SHA384Digest::new, SHA512Digest::new,
                () -> new SHA512tDigest(224), () -> new SHA512tDigest(256),
                () -> new SHA3Digest(224), () -> new SHA3Digest(256), () -> new SHA3Digest(384), () -> new SHA3Digest(512),
                () -> new KeccakDigest(256), () -> new KeccakDigest(512),
                RIPEMD128Digest::new, RIPEMD160Digest::new, RIPEMD256Digest::new, RIPEMD320Digest::new,
                WhirlpoolDigest::new, TigerDigest::new,
                GOST3411Digest::new, GOST3411_2012_256Digest::new, GOST3411_2012_512Digest::new,
                SM3Digest::new, () -> new DSTU7564Digest(256), () -> new DSTU7564Digest(512),
                () -> new Blake2bDigest(256), () -> new Blake2bDigest(512),
                () -> new Blake2sDigest(128), () -> new Blake2sDigest(256),
                Blake3Digest::new,
                () -> new SkeinDigest(SkeinDigest.SKEIN_256, 256),
                () -> new SkeinDigest(SkeinDigest.SKEIN_512, 512),
                () -> new SkeinDigest(SkeinDigest.SKEIN_1024, 1024));
        for (Supplier<Digest> supplier : digests) {
            Digest d = supplier.get();
            step(d.getAlgorithmName(), () -> {
                d.update(MSG, 0, MSG.length);
                byte[] out = new byte[d.getDigestSize()];
                d.doFinal(out, 0);
                info(d.getAlgorithmName() + " (" + d.getDigestSize() + " bytes)", shortHex(out));
            });
        }
        step("Digest state copy via Memoable", () -> {
            SHA256Digest a = new SHA256Digest();
            a.update(MSG, 0, 10);
            SHA256Digest b = new SHA256Digest(a);
            a.update(MSG, 10, MSG.length - 10);
            b.update(MSG, 10, MSG.length - 10);
            byte[] x = new byte[32];
            byte[] y = new byte[32];
            a.doFinal(x, 0);
            b.doFinal(y, 0);
            require(java.util.Arrays.equals(x, y), "copied state diverged");
        });
    }

    private static void xofs() {
        section("Extendable-output functions (XOF) and SP 800-185 derived functions");
        step("SHAKE128 / SHAKE256 with arbitrary output length", () -> {
            for (int bits : new int[] {128, 256}) {
                SHAKEDigest shake = new SHAKEDigest(bits);
                shake.update(MSG, 0, MSG.length);
                byte[] out = new byte[64];
                shake.doFinal(out, 0, out.length);
                info("SHAKE" + bits + " -> 64 bytes", shortHex(out));
            }
        });
        step("cSHAKE128 / cSHAKE256 (customisation string)", () -> {
            for (int bits : new int[] {128, 256}) {
                CSHAKEDigest cshake = new CSHAKEDigest(bits, "name".getBytes(StandardCharsets.UTF_8),
                        "customisation".getBytes(StandardCharsets.UTF_8));
                cshake.update(MSG, 0, MSG.length);
                byte[] out = new byte[32];
                cshake.doFinal(out, 0, out.length);
                info("cSHAKE" + bits, shortHex(out));
            }
        });
        step("ParallelHash128 / 256", () -> {
            for (int bits : new int[] {128, 256}) {
                ParallelHash ph = new ParallelHash(bits, "S".getBytes(StandardCharsets.UTF_8), 8, 32);
                ph.update(MSG, 0, MSG.length);
                byte[] out = new byte[32];
                ph.doFinal(out, 0);
                info("ParallelHash" + bits, shortHex(out));
            }
        });
        step("TupleHash128 / 256 (unambiguous tuple hashing)", () -> {
            for (int bits : new int[] {128, 256}) {
                TupleHash th = new TupleHash(bits, "S".getBytes(StandardCharsets.UTF_8), 256);
                th.update("a".getBytes(StandardCharsets.UTF_8), 0, 1);
                th.update("bc".getBytes(StandardCharsets.UTF_8), 0, 2);
                byte[] out = new byte[32];
                th.doFinal(out, 0);
                info("TupleHash" + bits, shortHex(out));
            }
        });
        step("Blake3 as XOF (extended output)", () -> {
            Blake3Digest b3 = new Blake3Digest();
            b3.update(MSG, 0, MSG.length);
            byte[] out = new byte[64];
            ((Xof) b3).doFinal(out, 0, out.length);
            info("Blake3 -> 64 bytes", shortHex(out));
        });
    }

    private static void macs() {
        section("MACs");
        byte[] key = random(32);

        List<Supplier<Mac>> hmacs = List.of(
                () -> new HMac(new SHA1Digest()), () -> new HMac(new SHA256Digest()),
                () -> new HMac(new SHA512Digest()), () -> new HMac(new SHA3Digest(256)),
                () -> new HMac(new RIPEMD160Digest()), () -> new HMac(new WhirlpoolDigest()),
                () -> new HMac(new SM3Digest()), () -> new HMac(new Blake2bDigest(512)));
        for (Supplier<Mac> supplier : hmacs) {
            Mac mac = supplier.get();
            step(mac.getAlgorithmName(), () -> {
                info(mac.getAlgorithmName(), shortHex(compute(mac, new KeyParameter(key))));
            });
        }
        step("CMAC (AES) - NIST SP 800-38B", () -> {
            Mac mac = new CMac(AESEngine.newInstance());
            info(mac.getAlgorithmName(), shortHex(compute(mac, new KeyParameter(key))));
        });
        step("CMAC (3DES, 64-bit block)", () -> {
            Mac mac = new CMac(new DESedeEngine());
            info(mac.getAlgorithmName(), shortHex(compute(mac, new KeyParameter(random(24)))));
        });
        step("CBC-MAC (AES)", () -> {
            Mac mac = new CBCBlockCipherMac(AESEngine.newInstance());
            info(mac.getAlgorithmName(), shortHex(compute(mac, new KeyParameter(key))));
        });
        step("GMAC (AES-GCM authentication only)", () -> {
            Mac mac = new GMac(GCMBlockCipher.newInstance(AESEngine.newInstance()));
            info(mac.getAlgorithmName(), shortHex(compute(mac, new ParametersWithIV(new KeyParameter(key), random(12)))));
        });
        step("KMAC128 / KMAC256 (SP 800-185)", () -> {
            for (int bits : new int[] {128, 256}) {
                KMAC kmac = new KMAC(bits, "custom".getBytes(StandardCharsets.UTF_8));
                info(kmac.getAlgorithmName(), shortHex(compute(kmac, new KeyParameter(key))));
            }
        });
        step("Poly1305 (one-time authenticator)", () -> {
            CipherKeyGenerator gen = new Poly1305KeyGenerator();
            gen.init(new KeyGenerationParameters(RANDOM, 256));
            Mac mac = new Poly1305();
            info(mac.getAlgorithmName(), shortHex(compute(mac, new KeyParameter(gen.generateKey()))));
        });
        step("Poly1305-AES (nonce-based)", () -> {
            CipherKeyGenerator gen = new Poly1305KeyGenerator();
            gen.init(new KeyGenerationParameters(RANDOM, 256));
            byte[] k = gen.generateKey();
            // 32-byte key = 16 AES key bytes + 16 clamped r bytes
            Mac mac = new Poly1305(AESEngine.newInstance());
            info(mac.getAlgorithmName(), shortHex(compute(mac, new ParametersWithIV(new KeyParameter(k), random(16)))));
        });
        step("SipHash-2-4", () -> {
            Mac mac = new SipHash(2, 4);
            info(mac.getAlgorithmName(), shortHex(compute(mac, new KeyParameter(random(16)))));
        });
        step("Blake2b keyed hash (built-in MAC mode)", () -> {
            Blake2bDigest keyed = new Blake2bDigest(key, 32, null, null);
            keyed.update(MSG, 0, MSG.length);
            byte[] out = new byte[32];
            keyed.doFinal(out, 0);
            info("Blake2b-256 keyed", shortHex(out));
        });
        step("Skein-MAC-512", () -> {
            Mac mac = new SkeinMac(SkeinMac.SKEIN_512, 512);
            info(mac.getAlgorithmName(), shortHex(compute(mac, new KeyParameter(key))));
        });
        step("VMPC-MAC", () -> {
            Mac mac = new VMPCMac();
            info(mac.getAlgorithmName(), shortHex(compute(mac, new ParametersWithIV(new KeyParameter(random(16)), random(16)))));
        });
    }

    private static byte[] compute(Mac mac, CipherParameters params) {
        mac.init(params);
        mac.update(MSG, 0, MSG.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }
}
