package cryptodemo.jca;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.shortHex;
import static cryptodemo.DemoSupport.step;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

/** java.security.KeyPairGenerator and KeyFactory across every asymmetric algorithm in the JDK. */
public final class KeyPairDemo {

    private KeyPairDemo() {
    }

    public static void run() {
        section("RSA");
        for (int bits : new int[] {2048, 3072, 4096}) {
            step("RSA-" + bits, () -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(bits);
                KeyPair kp = kpg.generateKeyPair();
                require(((RSAPublicKey) kp.getPublic()).getModulus().bitLength() == bits, "wrong modulus size");
                info("provider", kpg.getProvider().getName());
            });
        }
        step("RSA with RSAKeyGenParameterSpec (public exponent F4)", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
            KeyPair kp = kpg.generateKeyPair();
            info("public exponent", ((RSAPublicKey) kp.getPublic()).getPublicExponent());
        });
        step("RSASSA-PSS key type", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSASSA-PSS");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            info("algorithm", kp.getPublic().getAlgorithm());
        });

        section("DSA / Diffie-Hellman");
        step("DSA-2048", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
            kpg.initialize(2048);
            info("format", kpg.generateKeyPair().getPublic().getFormat());
        });
        step("DiffieHellman-2048 (predefined safe-prime group)", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
            kpg.initialize(2048);
            info("algorithm", kpg.generateKeyPair().getPublic().getAlgorithm());
        });

        section("Elliptic curves");
        for (String curve : List.of("secp256r1", "secp384r1", "secp521r1")) {
            step("EC " + curve, () -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec(curve));
                KeyPair kp = kpg.generateKeyPair();
                info("field size", ((ECPublicKey) kp.getPublic()).getParams().getCurve().getField().getFieldSize());
            });
        }
        step("EC by key size (initialize(256))", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            kpg.generateKeyPair();
        });
        for (String alg : List.of("Ed25519", "Ed448", "EdDSA", "X25519", "X448", "XDH")) {
            step(alg, () -> {
                KeyPair kp = KeyPairGenerator.getInstance(alg).generateKeyPair();
                info(alg, kp.getPublic().getAlgorithm() + ", " + kp.getPublic().getEncoded().length + "-byte X.509 key");
            });
        }
        step("EdDSA / XDH with NamedParameterSpec", () -> {
            KeyPairGenerator eddsa = KeyPairGenerator.getInstance("EdDSA");
            eddsa.initialize(NamedParameterSpec.ED448);
            KeyPairGenerator xdh = KeyPairGenerator.getInstance("XDH");
            xdh.initialize(NamedParameterSpec.X448);
            info("EdDSA", eddsa.generateKeyPair().getPublic().getAlgorithm());
            info("XDH", xdh.generateKeyPair().getPublic().getAlgorithm());
        });

        section("Post-quantum (JDK 24+)");
        for (String alg : List.of("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ML-DSA")) {
            step(alg, () -> {
                KeyPair kp = KeyPairGenerator.getInstance(alg).generateKeyPair();
                info(alg, "public key " + kp.getPublic().getEncoded().length + " bytes");
            });
        }
        for (String alg : List.of("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-KEM")) {
            step(alg, () -> {
                KeyPair kp = KeyPairGenerator.getInstance(alg).generateKeyPair();
                info(alg, "public key " + kp.getPublic().getEncoded().length + " bytes");
            });
        }

        section("KeyFactory");
        step("RSA: X.509 / PKCS#8 encode and decode", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            require(pub.equals(kp.getPublic()) && priv.equals(kp.getPrivate()), "decoded keys differ");
            info("public format", pub.getFormat());
            info("private format", priv.getFormat());
        });
        step("RSA: RSAPublicKeySpec (modulus + exponent) and getKeySpec", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            RSAPublicKey rsaPub = (RSAPublicKey) kp.getPublic();
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey rebuilt = kf.generatePublic(new RSAPublicKeySpec(rsaPub.getModulus(), rsaPub.getPublicExponent()));
            require(rebuilt.equals(rsaPub), "rebuilt key differs");
            RSAPublicKeySpec spec = kf.getKeySpec(rebuilt, RSAPublicKeySpec.class);
            require(spec.getModulus().equals(rsaPub.getModulus()), "spec mismatch");
            RSAPrivateCrtKey crt = (RSAPrivateCrtKey) kp.getPrivate();
            info("CRT prime p bits", crt.getPrimeP().bitLength());
            info("public exponent", crt.getPublicExponent());
        });
        step("EC: ECPublicKeySpec from point + parameters", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            ECPublicKey pub = (ECPublicKey) kpg.generateKeyPair().getPublic();
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey rebuilt = kf.generatePublic(new ECPublicKeySpec(pub.getW(), pub.getParams()));
            require(rebuilt.equals(pub), "rebuilt key differs");
        });
        step("EdDSA: decode X.509 / PKCS#8", () -> {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            require(kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())).equals(kp.getPublic()),
                    "public mismatch");
            require(kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded())).equals(kp.getPrivate()),
                    "private mismatch");
        });
        step("ML-DSA / ML-KEM: decode X.509 / PKCS#8", () -> {
            for (String alg : new String[] {"ML-DSA-65", "ML-KEM-768"}) {
                KeyPair kp = KeyPairGenerator.getInstance(alg).generateKeyPair();
                KeyFactory kf = KeyFactory.getInstance(alg);
                require(kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded())).equals(kp.getPublic()),
                        alg + " public mismatch");
                require(kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded())).equals(kp.getPrivate()),
                        alg + " private mismatch");
            }
        });
        step("translateKey", () -> {
            KeyPair kp = KeyPairGenerator.getInstance("EC").generateKeyPair();
            PublicKey translated = (PublicKey) KeyFactory.getInstance("EC").translateKey(kp.getPublic());
            require(kp.getPublic().equals(translated), "translateKey mismatch");
        });
        step("PEM-encode a public key (Base64 of X.509 SubjectPublicKeyInfo)", () -> {
            KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            String pem = "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(kp.getPublic().getEncoded())
                    + "\n-----END PUBLIC KEY-----";
            info("PEM", pem.replace("\n", " | "));
            info("DER", shortHex(kp.getPublic().getEncoded()));
        });
    }
}
