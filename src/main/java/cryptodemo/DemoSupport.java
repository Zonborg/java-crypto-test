package cryptodemo;

import java.util.HexFormat;

/** Console helpers shared by all demos. */
public final class DemoSupport {

    @FunctionalInterface
    public interface Step {
        void run() throws Exception;
    }

    private static int passed;
    private static int failed;

    private DemoSupport() {
    }

    public static void banner(String title) {
        String line = "=".repeat(64);
        System.out.println();
        System.out.println(line);
        System.out.printf("  %s%n", title);
        System.out.println(line);
    }

    public static void section(String title) {
        System.out.println();
        System.out.println("--- " + title + " ---");
    }

    /** Runs one operation, reporting OK/FAIL without aborting the rest of the demo. */
    public static void step(String name, Step step) {
        try {
            step.run();
            passed++;
            System.out.println("  [OK]   " + name);
        } catch (Exception | LinkageError e) {
            failed++;
            System.out.println("  [FAIL] " + name + " -> " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    /** Reports an operation that does not apply on this platform; not counted as pass or fail. */
    public static void skip(String name, String reason) {
        System.out.println("  [SKIP] " + name + " -> " + reason);
    }

    public static void info(String label, Object value) {
        System.out.println("           " + label + ": " + value);
    }

    public static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    public static String hex(byte[] data) {
        return HexFormat.of().formatHex(data);
    }

    /** Hex, truncated for readability. */
    public static String shortHex(byte[] data) {
        String h = hex(data);
        return h.length() <= 48 ? h : h.substring(0, 48) + "... (" + data.length + " bytes)";
    }

    public static int passed() {
        return passed;
    }

    public static int failed() {
        return failed;
    }
}
