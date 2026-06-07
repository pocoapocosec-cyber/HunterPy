package io.hunterpy.gui.ui.panels;

import io.hunterpy.gui.model.ScanReport;
import io.hunterpy.gui.ui.Theme;
import io.hunterpy.gui.util.Json;

import javax.swing.BorderFactory;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.event.HyperlinkEvent;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Desktop;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Third tab: Google-dork suggestions, grouped by template, clickable. */
public final class DorksPanel extends JPanel {

    private final JEditorPane body;

    public DorksPanel() {
        super(new BorderLayout());
        setBackground(Theme.BG_PANEL);
        setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));

        JLabel banner = new JLabel(
            "<html><div style='padding:8px 16px;color:#94a3b8'>"
            + "These are <b>passive</b> dork suggestions — HunterPy never "
            + "scraped Google. Click any link to open the search in your browser."
            + "</div></html>");
        add(banner, BorderLayout.NORTH);

        body = new JEditorPane();
        body.setContentType("text/html");
        body.setEditable(false);
        body.setOpaque(true);
        body.setBackground(Theme.BG_PANEL);
        body.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED
                && e.getURL() != null) {
                try { Desktop.getDesktop().browse(URI.create(e.getURL().toString())); }
                catch (Exception ignored) { }
            }
        });

        JScrollPane sp = new JScrollPane(body);
        sp.setBorder(null);
        sp.getViewport().setBackground(Theme.BG_PANEL);
        add(sp, BorderLayout.CENTER);
    }

    public void load(ScanReport r) {
        body.setText(render(r.dorks()));
        body.setCaretPosition(0);
    }

    @SuppressWarnings("unchecked")
    private String render(Map<String, Object> dorks) {
        StringBuilder sb = new StringBuilder("<html><body style='"
            + "color:#e5e7eb;background:#1e293b;font-family:Segoe UI,Helvetica,Arial,sans-serif;"
            + "padding:16px;font-size:13px;line-height:1.55'>");

        List<Object> items = Json.asList(dorks.get("dorks"));
        if (items.isEmpty()) {
            sb.append("<p style='color:#94a3b8'>No dork suggestions generated.</p>");
            sb.append("</body></html>");
            return sb.toString();
        }

        Map<String, List<Map<String, Object>>> grouped = new LinkedHashMap<>();
        for (Object o : items) {
            Map<String, Object> d = Json.asMap(o);
            grouped.computeIfAbsent(Json.asString(d.get("template"), "custom"),
                                    k -> new java.util.ArrayList<>()).add(d);
        }

        for (Map.Entry<String, List<Map<String, Object>>> e : grouped.entrySet()) {
            List<Map<String, Object>> ds = e.getValue();
            String sev = Json.asString(ds.get(0).get("severity"), "info").toUpperCase();
            String desc = Json.asString(ds.get(0).get("description"), "");
            String hue = severityHex(sev);
            sb.append("<h3 style='margin-top:18px;color:").append(hue).append(";"
                + "border-bottom:1px solid #334155;padding-bottom:4px'>")
              .append(esc(e.getKey())).append(" &nbsp;<span style='font-size:11px;color:#94a3b8'>")
              .append(sev).append("</span></h3>");
            sb.append("<p style='color:#94a3b8;margin-top:0'>")
              .append(esc(desc)).append("</p>");

            sb.append("<ul style='padding-left:18px;margin:6px 0'>");
            for (Map<String, Object> d : ds) {
                String q = Json.asString(d.get("query"), "");
                String u = Json.asString(d.get("google_url"), "");
                sb.append("<li style='margin:4px 0'><a href='").append(esc(u))
                  .append("' style='color:#06b6d4;text-decoration:none'>")
                  .append(esc(q)).append("</a></li>");
            }
            sb.append("</ul>");
        }
        sb.append("</body></html>");
        return sb.toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String severityHex(String sev) {
        Color c = Theme.SEV_INFO;
        switch (sev) {
            case "CRITICAL": c = Theme.SEV_CRITICAL; break;
            case "HIGH":     c = Theme.SEV_HIGH;     break;
            case "MEDIUM":   c = Theme.SEV_MEDIUM;   break;
            case "LOW":      c = Theme.SEV_LOW;      break;
        }
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }
}
