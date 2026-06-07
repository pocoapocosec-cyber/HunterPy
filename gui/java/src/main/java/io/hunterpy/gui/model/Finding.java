package io.hunterpy.gui.model;

import io.hunterpy.gui.util.Json;

import java.util.List;
import java.util.Map;

/**
 * Immutable representation of one HunterPy finding.
 *
 * <p>This class mirrors the JSON schema produced by
 * {@code core/report_engine.py}. We keep it intentionally flat — the GUI
 * never re-classifies, it only displays.
 */
public final class Finding {

    public enum Tier {
        INTERESTING, COMMON, FALSE_ALARM, UNKNOWN;

        public static Tier of(String s) {
            if (s == null) return UNKNOWN;
            switch (s.toUpperCase()) {
                case "INTERESTING": return INTERESTING;
                case "COMMON":      return COMMON;
                case "FALSE_ALARM": return FALSE_ALARM;
                default:            return UNKNOWN;
            }
        }
    }

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN;

        public static Severity of(String s) {
            if (s == null) return UNKNOWN;
            try { return Severity.valueOf(s.toUpperCase()); }
            catch (IllegalArgumentException e) { return UNKNOWN; }
        }

        public int rank() {
            switch (this) {
                case CRITICAL: return 5;
                case HIGH:     return 4;
                case MEDIUM:   return 3;
                case LOW:      return 2;
                case INFO:     return 1;
                default:       return 0;
            }
        }
    }

    private final String id;
    private final String module;
    private final String type;
    private final String title;
    private final String description;
    private final String url;
    private final double cvss;
    private final double score;
    private final double confidence;
    private final String classificationReason;
    private final Severity severity;
    private final Tier tier;
    private final Map<String, Object> evidence;
    private final List<String> references;

    private Finding(String id, String module, String type, String title,
                    String description, String url, double cvss, double score,
                    double confidence, String reason,
                    Severity severity, Tier tier,
                    Map<String, Object> evidence, List<String> references) {
        this.id = id;
        this.module = module;
        this.type = type;
        this.title = title;
        this.description = description;
        this.url = url;
        this.cvss = cvss;
        this.score = score;
        this.confidence = confidence;
        this.classificationReason = reason;
        this.severity = severity;
        this.tier = tier;
        this.evidence = evidence;
        this.references = references;
    }

    @SuppressWarnings("unchecked")
    public static Finding fromMap(Map<String, Object> m) {
        return new Finding(
            Json.asString(m.get("id"),     ""),
            Json.asString(m.get("module"), ""),
            Json.asString(m.get("type"),   ""),
            Json.asString(m.get("title"),  ""),
            Json.asString(m.getOrDefault("description",
                          m.getOrDefault("details", "")), ""),
            Json.asString(m.get("url"),    ""),
            Json.asDouble(m.get("cvss"),   0.0),
            Json.asDouble(m.get("score"),  0.0),
            Json.asDouble(m.get("classification_confidence"),
                Json.asDouble(m.get("confidence"), 0.0)),
            Json.asString(m.get("classification_reason"), ""),
            Severity.of(Json.asString(m.get("severity"), "INFO")),
            Tier.of(Json.asString(m.get("classification"),
                    Json.asString(m.get("tier"), "COMMON"))),
            Json.asMap(m.get("evidence")),
            (List<String>) (List<?>) Json.asList(m.get("references"))
        );
    }

    public String id()                       { return id; }
    public String module()                   { return module; }
    public String type()                     { return type; }
    public String title()                    { return title; }
    public String description()              { return description; }
    public String url()                      { return url; }
    public double cvss()                     { return cvss; }
    public double score()                    { return score; }
    public double confidence()               { return confidence; }
    public String classificationReason()     { return classificationReason; }
    public Severity severity()               { return severity; }
    public Tier tier()                       { return tier; }
    public Map<String, Object> evidence()    { return evidence; }
    public List<String> references()         { return references; }

    @Override
    public String toString() {
        return tier + " " + severity + " " + title;
    }
}
