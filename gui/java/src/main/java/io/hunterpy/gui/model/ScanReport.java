package io.hunterpy.gui.model;

import io.hunterpy.gui.util.Json;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Loaded HunterPy JSON report. Holds findings + ancillary artifacts
 * (DNS records, WHOIS, baseline, attack chains, dorks).
 *
 * <p>This is the only IO type the UI consumes. Adding a new tab in the UI
 * means adding a getter here, not threading a new field through every
 * panel.
 */
public final class ScanReport {

    private final String target;
    private final String mode;
    private final String scanId;
    private final String startTime;
    private final String endTime;
    private final String duration;
    private final List<String> modulesRun;
    private final List<Finding> findings;
    private final Map<String, Object> baseline;
    private final List<Map<String, Object>> attackChains;
    private final Map<String, Object> dns;
    private final Map<String, Object> whois;
    private final Map<String, Object> dorks;
    private final List<String> findingsSummary;
    private final Map<String, Object> pocs;
    private final Map<String, Object> impacts;

    @SuppressWarnings("unchecked")
    public static ScanReport fromJson(Object root) {
        Map<String, Object> top = Json.asMap(root);
        Map<String, Object> meta = Json.asMap(top.get("meta"));
        if (meta.isEmpty()) meta = Json.asMap(top.get("metadata"));

        // findings can be: list[Finding]  OR  {INTERESTING:[],COMMON:[],FALSE_ALARM:[]}
        List<Finding> findings = new ArrayList<>();
        Object rawFindings = top.get("findings");
        if (rawFindings instanceof Map) {
            Map<String, Object> grouped = Json.asMap(rawFindings);
            for (String tier : new String[] {"INTERESTING", "COMMON", "FALSE_ALARM"}) {
                for (Object item : Json.asList(grouped.get(tier))) {
                    findings.add(Finding.fromMap(Json.asMap(item)));
                }
            }
        } else if (rawFindings instanceof List) {
            for (Object item : Json.asList(rawFindings)) {
                findings.add(Finding.fromMap(Json.asMap(item)));
            }
        }

        List<Map<String, Object>> chains = new ArrayList<>();
        for (Object c : Json.asList(top.get("attack_chains"))) {
            chains.add(Json.asMap(c));
        }

        return new ScanReport(
            Json.asString(meta.get("target"), "(unknown)"),
            Json.asString(meta.get("mode"),   "unknown"),
            Json.asString(meta.get("scan_id"), ""),
            Json.asString(meta.get("start_time"), ""),
            Json.asString(meta.get("end_time"),   ""),
            Json.asString(meta.get("duration"),   ""),
            (List<String>) (List<?>) Json.asList(meta.get("modules_run")),
            findings,
            Json.asMap(top.get("baseline")),
            chains,
            Json.asMap(top.get("dns")),
            Json.asMap(top.get("whois")),
            Json.asMap(top.get("dorks")),
            (List<String>) (List<?>) Json.asList(top.get("findings_summary")),
            Json.asMap(top.get("pocs")),
            Json.asMap(top.get("impacts"))
        );
    }

    private ScanReport(String target, String mode, String scanId,
                       String startTime, String endTime, String duration,
                       List<String> modulesRun, List<Finding> findings,
                       Map<String, Object> baseline,
                       List<Map<String, Object>> attackChains,
                       Map<String, Object> dns, Map<String, Object> whois,
                       Map<String, Object> dorks,
                       List<String> findingsSummary,
                       Map<String, Object> pocs, Map<String, Object> impacts) {
        this.target = target;
        this.mode = mode;
        this.scanId = scanId;
        this.startTime = startTime;
        this.endTime = endTime;
        this.duration = duration;
        this.modulesRun = modulesRun;
        this.findings = findings;
        this.baseline = baseline;
        this.attackChains = attackChains;
        this.dns = dns;
        this.whois = whois;
        this.dorks = dorks;
        this.findingsSummary = findingsSummary;
        this.pocs = pocs;
        this.impacts = impacts;
    }

    public String target()                          { return target; }
    public String mode()                            { return mode; }
    public String scanId()                          { return scanId; }
    public String startTime()                       { return startTime; }
    public String endTime()                         { return endTime; }
    public String duration()                        { return duration; }
    public List<String> modulesRun()                { return modulesRun; }
    public List<Finding> findings()                 { return findings; }
    public Map<String, Object> baseline()           { return baseline; }
    public List<Map<String, Object>> attackChains() { return attackChains; }
    public Map<String, Object> dns()                { return dns; }
    public Map<String, Object> whois()              { return whois; }
    public Map<String, Object> dorks()              { return dorks; }
    public List<String> findingsSummary()           { return findingsSummary; }
    public Map<String, Object> pocs()               { return pocs; }
    public Map<String, Object> impacts()            { return impacts; }

    // ---------- derived counts (cheap; called from EDT) ----------
    public Map<Finding.Tier, Integer> tierCounts() {
        Map<Finding.Tier, Integer> m = new LinkedHashMap<>();
        for (Finding.Tier t : Finding.Tier.values()) m.put(t, 0);
        for (Finding f : findings) m.merge(f.tier(), 1, Integer::sum);
        return m;
    }

    public Map<Finding.Severity, Integer> severityCounts() {
        Map<Finding.Severity, Integer> m = new LinkedHashMap<>();
        for (Finding.Severity s : Finding.Severity.values()) m.put(s, 0);
        for (Finding f : findings) m.merge(f.severity(), 1, Integer::sum);
        return m;
    }

    public List<String> modulesObserved() {
        return findings.stream()
                .map(Finding::module)
                .filter(s -> s != null && !s.isEmpty())
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }

    /** Look up a PoC for a given finding by reconstructing the same key
     *  used by reporting/poc_generator.py::_finding_key. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> pocFor(Finding f) {
        String key = (f.id() != null && !f.id().isEmpty())
                ? f.id()
                : f.module() + "|" + f.type() + "|" + f.url() + "|"
                + (f.title() == null ? "" : f.title().substring(
                    0, Math.min(60, f.title().length())));
        Object got = pocs.get(key);
        return got != null ? Json.asMap(got) : Collections.emptyMap();
    }

    public Map<String, Object> impactFor(Finding f) {
        String key = (f.id() != null && !f.id().isEmpty())
                ? f.id()
                : f.module() + "|" + f.type() + "|" + f.url() + "|"
                + (f.title() == null ? "" : f.title().substring(
                    0, Math.min(60, f.title().length())));
        Object got = impacts.get(key);
        return got != null ? Json.asMap(got) : Collections.emptyMap();
    }
}
