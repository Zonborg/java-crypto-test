package cryptodemo.jca;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.RC2ParameterSpec;

/** java.security.AlgorithmParameters and AlgorithmParameterGenerator. */
public final class AlgorithmParametersDemo {

    private AlgorithmParametersDemo() {
    }

    public static void run() {
        section("AlgorithmParameters (ASN.1 encode/decode)");
        step("AES with IvParameterSpec", () -> {
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            AlgorithmParameters params = AlgorithmParameters.getInstance("AES");
            params.init(new IvParameterSpec(iv));
            byte[] encoded = params.getEncoded();

            AlgorithmParameters decoded = AlgorithmParameters.getInstance("AES");
            decoded.init(encoded);
            require(Arrays.equals(iv, decoded.getParameterSpec(IvParameterSpec.class).getIV()), "IV mismatch");
            info("DER", shortHex(encoded));
        });
        step("GCM with GCMParameterSpec", () -> {
            AlgorithmParameters params = AlgorithmParameters.getInstance("GCM");
            params.init(new GCMParameterSpec(128, new byte[12]));
            GCMParameterSpec spec = params.getParameterSpec(GCMParameterSpec.class);
            info("tag length", spec.getTLen());
        });
        step("OAEP with OAEPParameterSpec", () -> {
            AlgorithmParameters params = AlgorithmParameters.getInstance("OAEP");
            params.init(new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            info("encoded", shortHex(params.getEncoded()));
            info("toString", params.toString().replace('\n', ' '));
        });
        step("RSASSA-PSS with PSSParameterSpec", () -> {
            AlgorithmParameters params = AlgorithmParameters.getInstance("RSASSA-PSS");
            params.init(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            PSSParameterSpec spec = params.getParameterSpec(PSSParameterSpec.class);
            info("salt length", spec.getSaltLength());
        });
        step("EC named curve (ECGenParameterSpec -> ECParameterSpec)", () -> {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
            info("curve field size", spec.getCurve().getField().getFieldSize());
            info("cofactor", spec.getCofactor());
            info("DER", shortHex(params.getEncoded()));
        });
        step("PBES2 (PBEWithHmacSHA256AndAES_256)", () -> {
            AlgorithmParameters params = AlgorithmParameters.getInstance("PBEWithHmacSHA256AndAES_256");
            params.init(new PBEParameterSpec(new byte[16], 10_000, new IvParameterSpec(new byte[16])));
            info("DER", shortHex(params.getEncoded()));
        });
        step("ChaCha20-Poly1305 nonce", () -> {
            AlgorithmParameters params = AlgorithmParameters.getInstance("ChaCha20-Poly1305");
            params.init(new IvParameterSpec(new byte[12]));
            info("DER", shortHex(params.getEncoded()));
        });
        step("DESede / Blowfish IV parameters", () -> {
            for (String alg : new String[] {"DESede", "Blowfish"}) {
                AlgorithmParameters params = AlgorithmParameters.getInstance(alg);
                params.init(new IvParameterSpec(new byte[8]));
                info(alg, shortHex(params.getEncoded()));
            }
        });
        step("RC2 with RC2ParameterSpec", () -> {
            AlgorithmParameters params = AlgorithmParameters.getInstance("RC2");
            params.init(new RC2ParameterSpec(128, new byte[8]));
            info("RC2", shortHex(params.getEncoded()));
        });

        section("AlgorithmParameterGenerator");
        step("DSA (1024-bit, FIPS 186 domain parameters)", () -> {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DSA");
            gen.init(1024);
            AlgorithmParameters params = gen.generateParameters();
            DSAParameterSpec spec = params.getParameterSpec(DSAParameterSpec.class);
            info("p bits / q bits", spec.getP().bitLength() + " / " + spec.getQ().bitLength());
        });
        step("DiffieHellman (512-bit, small to keep generation fast)", () -> {
            AlgorithmParameterGenerator gen = AlgorithmParameterGenerator.getInstance("DiffieHellman");
            gen.init(512);
            AlgorithmParameters params = gen.generateParameters();
            DHParameterSpec spec = params.getParameterSpec(DHParameterSpec.class);
            info("p bits / g", spec.getP().bitLength() + " / " + spec.getG());
        });
    }
}
