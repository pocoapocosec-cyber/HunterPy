package io.hunterpy.gui.ui.panels;

import io.hunterpy.gui.model.ScanReport;
import io.hunterpy.gui.ui.Theme;
import io.hunterpy.gui.util.Json;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.util.List;
import java.util.Map;

/** Second tab: DNS / WHOIS / baseline — pretty plain-text dumps. */
public final class TargetPanel extends JPanel {

    private final JTextArea dnsArea = mono();
    private final JTextArea whoisArea = mono();
    private final JTextArea baselineArea = mono();

    public TargetPanel() {
        super(new BorderLayout());
        setBackground(Theme.BG_PANEL);
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel grid = new JPanel(new GridLayout(1, 3, 12, 12));
        grid.setOpaque(false);
        grid.add(card("DNS records", dnsArea));
        grid.add(card("WHOIS",       whoisArea));
        grid.add(card("Behavior baseline", baselineArea));
        add(grid, BorderLayout.CENTER);
    }

    public void load(ScanReport r) {
        dnsArea.setText(renderDns(r.dns()));
        whoisArea.setText(renderWhois(r.whois()));
        baselineArea.setText(renderBaseline(r.baseline()));
    }

    // ---------- formatters ----------
    private static String renderDns(Map<String, Object> dns) {
        if (dns == null || dns.isEmpty()) return "(no DNS data)";
        StringBuilder sb = new StringBuilder();
        appendList(sb, "A",     Json.asList(dns.get("a")));
        appendList(sb, "AAAA",  Json.asList(dns.get("aaaa")));
        appendList(sb, "NS",    Json.asList(dns.get("ns")));
        appendList(sb, "TXT",   Json.asList(dns.get("txt")));
        List<Object> mx = Json.asList(dns.get("mx"));
        if (!mx.isEmpty()) {
            sb.append("MX\n");
            for (Object m : mx) {
                if (m instanceof Map) {
                    Map<String, Object> mm = Json.asMap(m);
                    sb.append("  ").append(Json.asInt(mm.get("priority"), 0))
                      .append("  ").append(Json.asString(mm.get("mail_server"), ""))
                      .append("\n");
                } else {
                    sb.append("  ").append(m).append("\n");
                }
            }
            sb.append("\n");
        }
        Object cname = dns.get("cname");
        if (cname != null) sb.append("CNAME\n  ").append(cname).append("\n");
        return sb.length() == 0 ? "(no DNS data)" : sb.toString();
    }

    private static String renderWhois(Map<String, Object> w) {
        if (w == null || w.isEmpty()) return "(no WHOIS data)";
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Object> e : w.entrySet()) {
            if (e.getValue() == null) continue;
            sb.append(pad(e.getKey(), 16)).append(": ").append(e.getValue()).append("\n");
        }
        return sb.toString();
    }

    private static String renderBaseline(Map<String, Object> b) {
        if (b == null || b.isEmpty()) return "(no baseline established)";
        StringBuilder sb = new StringBuilder();
        sb.append("samples:          ").append(Json.asInt(b.get("samples"), 0)).append("\n");
        sb.append("server header:    ").append(Json.asString(b.get("server_header"), "?")).append("\n");
        sb.append("waf signature:    ").append(Json.asString(b.get("waf_signature"), "?")).append("\n");
        sb.append("length mean:      ").append(fmt(b.get("length_mean"))).append("\n");
        sb.append("length stdev:     ").append(fmt(b.get("length_stdev"))).append("\n");
        sb.append("length p95:       ").append(fmt(b.get("length_p95"))).append("\n");
        sb.append("latency mean ms:  ").append(fmt(b.get("latency_mean_ms"))).append("\n");
        sb.append("latency stdev ms: ").append(fmt(b.get("latency_stdev_ms"))).append("\n");
        sb.append("404 sizes seen:   ")
          .append(Json.asList(b.get("common_404_bodies"))).append("\n");
        sb.append("status counts:    ").append(Json.asMap(b.get("status_distribution"))).append("\n");
        return sb.toString();
    }

    private static String fmt(Object v) {
        if (v == null) return "—";
        if (v instanceof Number) return String.format("%.2f", ((Number) v).doubleValue());
        return v.toString();
    }

    private static String pad(String s, int n) {
        StringBuilder b = new StringBuilder(s);
        while (b.length() < n) b.append(' ');
        return b.toString();
    }

    private static void appendList(StringBuilder sb, String name, List<Object> values) {
        if (values == null || values.isEmpty()) return;
        sb.append(name).append("\n");
        for (Object v : values) sb.append("  ").append(v).append("\n");
        sb.append("\n");
    }

    private static JTextArea mono() {
        JTextArea a = new JTextArea();
        a.setEditable(false);
        a.setBackground(Theme.BG_DEEP);
        a.setForeground(Theme.TEXT);
        a.setFont(Theme.MONO);
        a.setMargin(new java.awt.Insets(8, 10, 8, 10));
        return a;
    }

    private static JPanel card(String title, JTextArea area) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(Theme.BG_PANEL);
        p.setBorder(BorderFactory.createLineBorder(Theme.LINE));
        JLabel t = new JLabel("  " + title.toUpperCase());
        t.setFont(Theme.UI_BOLD.deriveFont(11f));
        t.setForeground(Theme.BRAND);
        t.setBorder(BorderFactory.createEmptyBorder(6, 0, 6, 0));
        p.add(t, BorderLayout.NORTH);
        JScrollPane sp = new JScrollPane(area);
        sp.setBorder(null);
        p.add(sp, BorderLayout.CENTER);
        return p;
    }
}
