package cryptodemo.jca;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.skip;
import static cryptodemo.DemoSupport.step;

import java.nio.charset.StandardCharsets;
import java.security.DrbgParameters;
import java.security.DrbgParameters.Capability;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.security.Security;
import java.util.List;
import java.util.Locale;
import java.util.random.RandomGenerator;

/** java.security.SecureRandom: algorithms, DRBG parameters and RandomGenerator API. */
public final class SecureRandomDemo {

    private SecureRandomDemo() {
    }

    public static void run() {
        section("Algorithms");
        step("new SecureRandom() (platform default)", () -> {
            SecureRandom sr = new SecureRandom();
            info("algorithm", sr.getAlgorithm());
            info("provider", sr.getProvider().getName());
        });
        step("getInstanceStrong()", () -> {
            SecureRandom sr = SecureRandom.getInstanceStrong();
            info("algorithm", sr.getAlgorithm());
        });
        for (String alg : List.of("DRBG", "SHA1PRNG", "NativePRNG", "NativePRNGBlocking", "NativePRNGNonBlocking", "Windows-PRNG")) {
            if (!Security.getAlgorithms("SecureRandom").contains(alg.toUpperCase(Locale.ROOT))) {
                skip(alg, "not available on this platform");
                continue;
            }
            step(alg, () -> {
                SecureRandom sr = SecureRandom.getInstance(alg);
                byte[] bytes = new byte[16];
                sr.nextBytes(bytes);
                info(alg + " [" + sr.getProvider().getName() + "]", shortHex(bytes));
            });
        }

        section("DRBG with parameters (NIST SP 800-90A)");
        step("Instantiate with strength, prediction resistance and personalization", () -> {
            SecureRandom drbg = SecureRandom.getInstance("DRBG",
                    DrbgParameters.instantiation(256, Capability.PR_AND_RESEED,
                            "java-crypto-test".getBytes(StandardCharsets.UTF_8)));
            info("parameters", drbg.getParameters());
        });
        step("nextBytes(byte[], SecureRandomParameters) with prediction resistance", () -> {
            SecureRandom drbg = SecureRandom.getInstance("DRBG",
                    DrbgParameters.instantiation(256, Capability.PR_AND_RESEED, null));
            byte[] out = new byte[32];
            drbg.nextBytes(out, DrbgParameters.nextBytes(256, true, null));
            info("output", shortHex(out));
        });
        step("reseed() and reseed(SecureRandomParameters)", () -> {
            SecureRandom drbg = SecureRandom.getInstance("DRBG",
                    DrbgParameters.instantiation(128, Capability.RESEED_ONLY, null));
            drbg.reseed();
            SecureRandomParameters reseed = DrbgParameters.reseed(false, null);
            drbg.reseed(reseed);
        });

        section("Generating values");
        SecureRandom sr = new SecureRandom();
        step("nextBytes / generateSeed / getSeed", () -> {
            byte[] a = new byte[16];
            sr.nextBytes(a);
            info("nextBytes", shortHex(a));
            info("generateSeed", shortHex(sr.generateSeed(16)));
            info("SecureRandom.getSeed", shortHex(SecureRandom.getSeed(8)));
        });
        step("nextInt / nextInt(bound) / nextInt(origin, bound) / nextLong / nextBoolean", () -> {
            info("nextInt", sr.nextInt());
            info("nextInt(100)", sr.nextInt(100));
            info("nextInt(10, 20)", sr.nextInt(10, 20));
            info("nextLong", sr.nextLong());
            info("nextBoolean", sr.nextBoolean());
        });
        step("nextFloat / nextDouble / nextGaussian", () -> {
            info("nextFloat", sr.nextFloat());
            info("nextDouble", sr.nextDouble());
            info("nextGaussian", sr.nextGaussian());
        });
        step("ints(count, min, max) stream", () -> {
            int[] dice = sr.ints(5, 1, 7).toArray();
            require(dice.length == 5, "wrong count");
            info("dice", java.util.Arrays.toString(dice));
        });
        step("setSeed supplements (does not replace) entropy", () -> {
            SecureRandom r = new SecureRandom();
            r.setSeed(42L);
            r.setSeed(new byte[] {1, 2, 3});
            r.nextInt();
        });
        step("RandomGenerator interface", () -> {
            RandomGenerator g = new SecureRandom();
            info("nextLong(1000)", g.nextLong(1000));
        });
    }
}
