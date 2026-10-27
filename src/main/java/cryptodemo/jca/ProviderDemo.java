package cryptodemo.jca;

import static cryptodemo.DemoSupport.info;
import static cryptodemo.DemoSupport.require;
import static cryptodemo.DemoSupport.section;
import static cryptodemo.DemoSupport.step;

import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import javax.crypto.Cipher;

/** java.security.Provider and Security: installed providers, supported algorithms and policy. */
public final class ProviderDemo {

    /** Minimal custom provider to show registration; it registers no algorithms. */
    private static final class DemoProvider extends Provider {
        private static final long serialVersionUID = 1L;

        DemoProvider() {
            super("DemoProvider", "1.0", "Example provider registered at runtime");
        }
    }

    private ProviderDemo() {
    }

    public static void run() {
        section("Installed providers");
        step("Security.getProviders()", () -> {
            for (Provider p : Security.getProviders()) {
                info(p.getName() + " " + p.getVersionStr(), p.getInfo());
            }
        });

        section("Services per provider");
        step("Count services by type", () -> {
            for (Provider p : Security.getProviders()) {
                Map<String, Integer> counts = new TreeMap<>();
                for (Provider.Service s : p.getServices()) {
                    counts.merge(s.getType(), 1, Integer::sum);
                }
                info(p.getName(), counts);
            }
        });

        section("Algorithms by service type (Security.getAlgorithms)");
        for (String type : new String[] {"MessageDigest", "Mac", "Cipher", "KeyGenerator", "SecretKeyFactory",
                "KeyPairGenerator", "KeyFactory", "Signature", "KeyAgreement", "KEM", "KDF", "SecureRandom",
                "KeyStore", "AlgorithmParameters", "AlgorithmParameterGenerator", "CertificateFactory",
                "CertPathValidator", "CertPathBuilder", "CertStore"}) {
            step(type, () -> {
                Set<String> algs = Security.getAlgorithms(type);
                info(type + " (" + algs.size() + ")", String.join(", ", new java.util.TreeSet<>(algs)));
            });
        }

        section("Provider lookup");
        step("Security.getProvider / Provider.getService / Service attributes", () -> {
            Provider sunJce = Security.getProvider("SunJCE");
            Provider.Service svc = sunJce.getService("Cipher", "AES/GCM/NoPadding");
            require(svc != null, "service not found");
            info("class", svc.getClassName());
            info("supported modes", svc.getAttribute("SupportedModes"));
            info("supported paddings", svc.getAttribute("SupportedPaddings"));
        });
        step("Provider.getProperty / Provider.entrySet", () -> {
            Provider sun = Security.getProvider("SUN");
            info("SUN version", sun.getProperty("Provider.id version"));
            info("entry count", sun.entrySet().size());
        });
        step("Cipher.getInstance(transformation, providerName) selects a specific provider", () -> {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
            info("provider", c.getProvider().getName());
        });

        section("Runtime provider management");
        step("Security.addProvider / insertProviderAt / removeProvider", () -> {
            int pos = Security.addProvider(new DemoProvider());
            info("added at position", pos);
            require(Security.getProvider("DemoProvider") != null, "provider not registered");
            Security.removeProvider("DemoProvider");
            require(Security.getProvider("DemoProvider") == null, "provider not removed");
        });

        section("Security properties and policy");
        step("Security.getProperty", () -> {
            for (String key : new String[] {"securerandom.source", "keystore.type", "jdk.tls.disabledAlgorithms",
                    "jdk.certpath.disabledAlgorithms", "jdk.jar.disabledAlgorithms", "crypto.policy"}) {
                info(key, Security.getProperty(key));
            }
        });
        step("Unlimited-strength policy: Cipher.getMaxAllowedKeyLength", () -> {
            int max = Cipher.getMaxAllowedKeyLength("AES");
            require(max >= 256, "restricted crypto policy: " + max);
            info("AES max key length", max);
        });
    }
}
