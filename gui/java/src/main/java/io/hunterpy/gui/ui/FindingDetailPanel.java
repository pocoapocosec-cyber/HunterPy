package io.hunterpy.gui.ui;

import io.hunterpy.gui.model.Finding;
import io.hunterpy.gui.model.ScanReport;
import io.hunterpy.gui.ui.widgets.Pill;
import io.hunterpy.gui.util.Json;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.SwingConstants;
import javax.swing.event.HyperlinkEvent;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Right-hand pane showing the full finding detail (PoC, impact,
 * evidence, references). Built around an {@link JEditorPane} with
 * inline-styled HTML so we don't need a templating engine.
 */
public final class FindingDetailPanel extends JPanel {

    private final JEditorPane body;
    private final JPanel header;

    public FindingDetailPanel() {
        super(new BorderLayout());
        setBackground(Theme.BG_PANEL);
        setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBackground(Theme.BG_PANEL);
        header.setBorder(BorderFactory.createEmptyBorder(14, 16, 8, 16));

        body = new JEditorPane();
        body.setContentType("text/html");
        body.setEditable(false);
        body.setOpaque(false);
        body.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
                openLink(e.getURL() != null ? e.getURL().toString() : e.getDescription());
            }
        });

        showPlaceholder();

        add(header, BorderLayout.NORTH);
        JScrollPane sp = new JScrollPane(body);
        sp.setBorder(null);
        sp.getViewport().setBackground(Theme.BG_PANEL);
        add(sp, BorderLayout.CENTER);
    }

    private void showPlaceholder() {
        header.removeAll();
        header.add(label("Select a finding to view details", Theme.TEXT_DIM,
                         Theme.UI_FONT.deriveFont(14f)));
        header.revalidate();
        body.setText(html("<p style='color:#94a3b8'>Click a row on the left.</p>"));
        body.setCaretPosition(0);
    }

    public void show(Finding f, ScanReport report) {
        if (f == null) { showPlaceholder(); return; }

        header.removeAll();

        JPanel badges = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        badges.setOpaque(false);
        badges.add(new Pill(f.tier().toString(),     Theme.colorFor(f.tier())));
        badges.add(new Pill(f.severity().toString(), Theme.colorFor(f.severity())));
        if (f.score() > 0) {
            badges.add(label(String.format("score %.2f", f.score()), Theme.TEXT_DIM,
                             Theme.UI_FONT.deriveFont(11f)));
        }
        if (f.cvss() > 0) {
            badges.add(label("cvss " + f.cvss(), Theme.TEXT_DIM,
                             Theme.UI_FONT.deriveFont(11f)));
        }
        badges.add(label("[" + f.module() + "]", Theme.TEXT_DIM,
                         Theme.UI_FONT.deriveFont(11f)));
        header.add(badges);

        header.add(Box.createVerticalStrut(6));
        JLabel title = label(f.title(), Theme.TEXT, Theme.HEADER);
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        header.add(title);

        if (f.url() != null && !f.url().isEmpty()) {
            JLabel url = label(f.url(), Theme.BRAND, Theme.MONO.deriveFont(11f));
            header.add(url);
        }
        header.revalidate();
        header.repaint();

        body.setText(html(renderBody(f, report)));
        body.setCaretPosition(0);
    }

    // ---------- body content ----------
    private String renderBody(Finding f, ScanReport report) {
        StringBuilder sb = new StringBuilder();

        if (f.description() != null && !f.description().isEmpty()) {
            sb.append(h2("Description"))
              .append(p(esc(f.description())));
        }

        if (f.classificationReason() != null && !f.classificationReason().isEmpty()) {
            sb.append("<p style='color:#94a3b8;font-size:12px'>"
                      + "Reasoning: " + esc(f.classificationReason())
                      + " (confidence " + Math.round(f.confidence() * 100) + "%)"
                      + "</p>");
        }

        // Impact
        Map<String, Object> impact = report.impactFor(f);
        if (!impact.isEmpty()) {
            sb.append(h2("Impact"));
            sb.append(kv("Priority",      Json.asString(impact.get("priority_tier"), "?")));
            sb.append(kv("Suggested SLA", Json.asString(impact.get("suggested_sla"), "?")));
            sb.append(kv("Data at risk",  Json.asString(impact.get("data_at_risk"), "?")));
            List<Object> comps = Json.asList(impact.get("compliance_hints"));
            if (!comps.isEmpty()) {
                sb.append(kv("Compliance", String.join(", ", asStrings(comps))));
            }
        }

        // PoC
        Map<String, Object> poc = report.pocFor(f);
        if (!poc.isEmpty()) {
            sb.append(h2("Verification (proof of concept)"));
            sb.append(p(esc(Json.asString(poc.get("description"), ""))));
            List<Object> steps = Json.asList(poc.get("steps"));
            if (!steps.isEmpty()) {
                sb.append("<ol>");
                for (Object s : steps) sb.append("<li>").append(esc(s.toString())).append("</li>");
                sb.append("</ol>");
            }
            String cmd = Json.asString(poc.get("sample_command"), "");
            if (!cmd.isEmpty()) {
                sb.append("<p><b>Sample command</b></p>");
                sb.append(code(cmd));
            }
            String rem = Json.asString(poc.get("remediation"), "");
            if (!rem.isEmpty()) {
                sb.append(h2("Remediation"));
                sb.append(p(esc(rem)));
            }
            List<Object> refs = Json.asList(poc.get("references"));
            if (!refs.isEmpty()) {
                sb.append(h2("References"));
                sb.append("<ul>");
                for (Object r : refs) {
                    String url = r.toString();
                    sb.append("<li><a href='").append(esc(url))
                      .append("' style='color:#06b6d4'>").append(esc(url))
                      .append("</a></li>");
                }
                sb.append("</ul>");
            }
        }

        // Evidence
        Map<String, Object> ev = f.evidence();
        if (ev != null && !ev.isEmpty()) {
            sb.append(h2("Evidence"));
            sb.append("<table style='border-collapse:collapse;width:100%'>");
            for (Map.Entry<String, Object> e : ev.entrySet()) {
                sb.append("<tr><td style='vertical-align:top;color:#94a3b8;"
                          + "padding:4px 12px 4px 0'>")
                  .append(esc(e.getKey())).append("</td><td style='padding:4px 0'>")
                  .append(esc(stringify(e.getValue()))).append("</td></tr>");
            }
            sb.append("</table>");
        }

        return sb.toString();
    }

    // ---------- HTML helpers ----------
    private String html(String inner) {
        return "<html><head><style>"
             + "body{font-family:Segoe UI,Helvetica,Arial,sans-serif;"
             + "color:#e5e7eb;background:#1e293b;padding:0 16px 16px 16px;"
             + "font-size:13px;line-height:1.55}"
             + "h2{color:#06b6d4;font-size:13px;border-bottom:1px solid #334155;"
             + "padding-bottom:4px;margin-top:18px;margin-bottom:6px;"
             + "text-transform:uppercase;letter-spacing:1px;}"
             + "code,pre{background:#0b1220;color:#a5e3ff;padding:4px 8px;"
             + "border-radius:4px;font-family:monospace;font-size:12px;"
             + "white-space:pre-wrap}"
             + "a{color:#06b6d4;text-decoration:none}"
             + "</style></head><body>" + inner + "</body></html>";
    }

    private String h2(String s)               { return "<h2>" + esc(s) + "</h2>"; }
    private String p(String s)                { return "<p>" + s + "</p>"; }
    private String code(String s)             { return "<pre>" + esc(s) + "</pre>"; }
    private String kv(String k, String v) {
        return "<p style='margin:2px 0'><b style='color:#94a3b8'>"
             + esc(k) + ":</b> " + esc(v) + "</p>";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String stringify(Object o) {
        if (o == null) return "—";
        if (o instanceof List || o instanceof Map) return o.toString();
        return o.toString();
    }

    private static List<String> asStrings(List<Object> in) {
        java.util.ArrayList<String> out = new java.util.ArrayList<>(in.size());
        for (Object o : in) out.add(o == null ? "" : o.toString());
        return out;
    }

    private static JLabel label(String text, Color color, java.awt.Font font) {
        JLabel l = new JLabel(text, SwingConstants.LEFT);
        l.setFont(font); l.setForeground(color);
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        return l;
    }

    private static void openLink(String url) {
        if (url == null || url.isEmpty()) return;
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
            }
        } catch (Exception ignored) { }
    }
}
