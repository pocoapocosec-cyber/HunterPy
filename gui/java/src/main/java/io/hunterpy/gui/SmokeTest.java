package io.hunterpy.gui;

import io.hunterpy.gui.io.ReportLoader;
import io.hunterpy.gui.model.Finding;
import io.hunterpy.gui.model.ScanReport;
import io.hunterpy.gui.util.Json;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Headless smoke test — verifies the JSON parser, models, and accessors
 * work without booting Swing. Used by build.sh and CI.
 *
 * <p>Exits 0 on success, non-zero on first assertion failure.</p>
 */
public final class SmokeTest {

    public static void main(String[] args) throws Exception {
        int failures = 0;
        failures += testJsonPrimitives();
        failures += testJsonNested();
        failures += testLoadSampleReport();

        if (failures > 0) {
            System.err.println("FAIL: " + failures + " assertion(s) failed.");
            System.exit(1);
        }
        System.out.println("OK — smoke tests passed.");
    }

    private static int testJsonPrimitives() {
        int f = 0;
        f += assertEq("string", "hello", Json.parse("\"hello\""));
        f += assertEq("escaped string", "tab\there", Json.parse("\"tab\\there\""));
        f += assertEq("number", 42.5, Json.parse("42.5"));
        f += assertEq("bool true",  Boolean.TRUE,  Json.parse("true"));
        f += assertEq("bool false", Boolean.FALSE, Json.parse("false"));
        f += assertEq("null", null, Json.parse("null"));
        return f;
    }

    @SuppressWarnings("unchecked")
    private static int testJsonNested() {
        int f = 0;
        Object root = Json.parse("{\"a\":[1,2,{\"b\":\"c\"}],\"d\":null}");
        Map<String, Object> m = Json.asMap(root);
        f += assertEq("nested keys",  2, m.size());
        List<Object> arr = Json.asList(m.get("a"));
        f += assertEq("array length", 3, arr.size());
        f += assertEq("array index",  2.0, arr.get(1));
        f += assertEq("deep value", "c",
            Json.asString(Json.asMap(arr.get(2)).get("b"), ""));
        return f;
    }

    private static int testLoadSampleReport() throws Exception {
        int f = 0;
        Path sample = locateSample();
        if (sample == null) {
            System.err.println("WARN: sample report not found; skipping load test");
            return 0;
        }
        ScanReport r = ReportLoader.load(sample);
        f += assertCondition("findings non-empty", !r.findings().isEmpty());
        f += assertCondition("target set", r.target() != null && !r.target().isEmpty());
        f += assertCondition("mode set",   r.mode()   != null && !r.mode().isEmpty());

        // Derived counters
        Map<Finding.Tier, Integer> tiers = r.tierCounts();
        int sumTiers = tiers.values().stream().mapToInt(Integer::intValue).sum();
        f += assertEq("tier counts sum to total findings", r.findings().size(), sumTiers);

        // Severity counts
        Map<Finding.Severity, Integer> sev = r.severityCounts();
        int sumSev = sev.values().stream().mapToInt(Integer::intValue).sum();
        f += assertEq("severity counts sum to total findings", r.findings().size(), sumSev);

        // PoC lookup for first finding
        if (!r.findings().isEmpty()) {
            Finding first = r.findings().get(0);
            Map<String, Object> poc = r.pocFor(first);
            // PoC may or may not exist for every finding — just ensure
            // the lookup doesn't crash and returns a map.
            f += assertCondition("pocFor returns map", poc != null);
        }
        return f;
    }

    private static Path locateSample() {
        String[] candidates = {
            "samples/sample_scan.json",
            "../samples/sample_scan.json",
            "../../samples/sample_scan.json",
            "../../../samples/sample_scan.json",
        };
        for (String c : candidates) {
            Path p = Paths.get(c);
            if (p.toFile().isFile()) return p;
        }
        return null;
    }

    // ---------- micro-assertions ----------
    private static int assertEq(String label, Object expected, Object actual) {
        boolean ok = (expected == null && actual == null)
            || (expected != null && expected.equals(actual));
        if (!ok) {
            System.err.println("  FAIL " + label
                + ": expected <" + expected + "> got <" + actual + ">");
            return 1;
        }
        System.out.println("  ok   " + label);
        return 0;
    }

    private static int assertCondition(String label, boolean cond) {
        if (!cond) {
            System.err.println("  FAIL " + label);
            return 1;
        }
        System.out.println("  ok   " + label);
        return 0;
    }
}
