package io.hunterpy.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMapFilter;

import javax.swing.*;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The "HunterPy" tab inside Burp. Lets the user:
 *   • load a HunterPy JSON report
 *   • review findings in a sortable / filterable table
 *   • send INTERESTING URLs to Burp's Site Map (synthetic GET request)
 *   • send a single selected URL to Repeater
 *   • emit findings as Burp audit issues into the Site Map's issues view
 *
 * <p>This class is intentionally Swing-only and stateless beyond the
 * currently loaded report. No network, no disk writes.</p>
 */
final class HunterPyTab {

    private final MontoyaApi api;
    private final JPanel root = new JPanel(new BorderLayout());
    private final FindingsModel model = new FindingsModel();
    private final JTable table = new JTable(model);
    private final JLabel status = new JLabel(" Load a HunterPy report to begin.");
    private final JTextArea detail = new JTextArea();

    HunterPyTab(MontoyaApi api) {
        this.api = api;

        // Toolbar
        JToolBar tb = new JToolBar();
        tb.setFloatable(false);

        JButton load = new JButton("Load report…");
        load.addActionListener(e -> loadReport());

        JButton sendSiteMap = new JButton("Add to Site Map");
        sendSiteMap.setToolTipText(
            "Adds a synthetic GET request for each visible finding URL to Burp's Site Map.");
        sendSiteMap.addActionListener(e -> addVisibleFindingsToSiteMap());

        JButton sendRepeater = new JButton("Send selected → Repeater");
        sendRepeater.addActionListener(e -> sendSelectedToRepeater());

        JButton emitIssues = new JButton("Emit issues");
        emitIssues.setToolTipText(
            "Emits each visible finding as a Burp AuditIssue so it shows up "
            + "in the Issues tab next to Burp's own findings.");
        emitIssues.addActionListener(e -> emitAuditIssuesForVisible());

        tb.add(load);
        tb.add(sendSiteMap);
        tb.add(sendRepeater);
        tb.add(emitIssues);
        tb.add(Box.createHorizontalGlue());

        JTextField filter = new JTextField(24);
        filter.setToolTipText("Filter rows by substring (title/url/module).");
        filter.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            void apply() { model.setFilter(filter.getText()); }
            public void insertUpdate(javax.swing.event.DocumentEvent e)  { apply(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e)  { apply(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { apply(); }
        });
        tb.add(new JLabel("Filter:"));
        tb.add(filter);

        // Table
        table.setAutoCreateRowSorter(true);
        table.setRowHeight(22);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        TableColumn sevCol = table.getColumnModel().getColumn(FindingsModel.COL_SEVERITY);
        sevCol.setCellRenderer(new SeverityCellRenderer());
        sevCol.setMaxWidth(110);
        table.getColumnModel().getColumn(FindingsModel.COL_TIER).setMaxWidth(120);
        table.getColumnModel().getColumn(FindingsModel.COL_MODULE).setMaxWidth(120);

        ListSelectionListener sel = e -> {
            if (e.getValueIsAdjusting()) return;
            int row = table.getSelectedRow();
            if (row >= 0) {
                int mr = table.convertRowIndexToModel(row);
                detail.setText(model.detailText(mr));
                detail.setCaretPosition(0);
            }
        };
        table.getSelectionModel().addListSelectionListener(sel);

        detail.setEditable(false);
        detail.setLineWrap(true);
        detail.setWrapStyleWord(true);
        detail.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            new JScrollPane(table), new JScrollPane(detail));
        split.setDividerLocation(720);
        split.setResizeWeight(0.6);

        root.add(tb, BorderLayout.NORTH);
        root.add(split, BorderLayout.CENTER);
        root.add(status, BorderLayout.SOUTH);
    }

    Component getRootComponent() { return root; }

    // ----------------------------------------------------------------
    // Actions
    // ----------------------------------------------------------------
    private void loadReport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Open HunterPy JSON report");
        chooser.setFileFilter(new FileNameExtensionFilter("HunterPy JSON (*.json)", "json"));
        if (chooser.showOpenDialog(root) != JFileChooser.APPROVE_OPTION) return;

        File f = chooser.getSelectedFile();
        try {
            Object json = MiniJson.parseFile(f.toPath());
            model.load(json);
            status.setText(String.format(" Loaded %d findings from %s",
                model.getRowCount(), f.getName()));
            api.logging().logToOutput("[HunterPy] loaded report: " + f);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(root,
                "Could not load report:\n" + ex.getMessage(),
                "Load error", JOptionPane.ERROR_MESSAGE);
            api.logging().logToError("[HunterPy] load failed: " + ex);
        }
    }

    private void addVisibleFindingsToSiteMap() {
        int added = 0;
        for (Finding f : model.visibleFindings()) {
            HttpRequest req = synthesizeRequest(f);
            if (req == null) continue;
            try {
                api.siteMap().add(HttpRequestResponse.httpRequestResponse(req, null));
                added++;
            } catch (Exception e) {
                api.logging().logToError("[HunterPy] siteMap.add failed: " + e);
            }
        }
        status.setText(" Added " + added + " synthetic request(s) to Site Map.");
    }

    private void sendSelectedToRepeater() {
        int row = table.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(root, "Select a finding first.");
            return;
        }
        Finding f = model.findingAt(table.convertRowIndexToModel(row));
        HttpRequest req = synthesizeRequest(f);
        if (req == null) {
            JOptionPane.showMessageDialog(root, "Finding has no URL to send.");
            return;
        }
        api.repeater().sendToRepeater(req, "HunterPy: " + safeShort(f.title, 40));
        status.setText(" Sent to Repeater: " + f.url);
    }

    private void emitAuditIssuesForVisible() {
        int emitted = 0;
        for (Finding f : model.visibleFindings()) {
            HttpRequest req = synthesizeRequest(f);
            if (req == null) continue;
            AuditIssue issue = AuditIssue.auditIssue(
                f.title,                                         // name
                buildIssueDetail(f),                             // detail
                buildIssueRemediation(f),                        // remediation
                f.url != null ? f.url : "",                      // baseUrl
                mapSeverity(f.severity),                         // severity
                mapConfidence(f.tier),                           // confidence
                buildBackground(f),                              // background
                "",                                              // remediation background
                AuditIssueSeverity.INFORMATION,                   // typical severity
                Collections.singletonList(
                    HttpRequestResponse.httpRequestResponse(req, null))
            );
            api.siteMap().add(issue);
            emitted++;
        }
        status.setText(" Emitted " + emitted + " audit issue(s) into Site Map.");
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------
    private HttpRequest synthesizeRequest(Finding f) {
        if (f == null || f.url == null || f.url.isEmpty()) return null;
        try {
            URI u = URI.create(f.url);
            String scheme = u.getScheme() == null ? "https" : u.getScheme();
            String host = u.getHost() == null ? "" : u.getHost();
            int port = u.getPort();
            if (port < 0) port = "https".equalsIgnoreCase(scheme) ? 443 : 80;
            HttpService svc = HttpService.httpService(host, port,
                "https".equalsIgnoreCase(scheme));
            String path = u.getRawPath() == null || u.getRawPath().isEmpty()
                ? "/" : u.getRawPath();
            if (u.getRawQuery() != null) path += "?" + u.getRawQuery();
            String raw = "GET " + path + " HTTP/1.1\r\n"
                + "Host: " + host + "\r\n"
                + "User-Agent: HunterPy-Burp-Bridge/2.0\r\n"
                + "Accept: */*\r\n\r\n";
            return HttpRequest.httpRequest(svc, raw);
        } catch (Exception e) {
            api.logging().logToError("[HunterPy] cannot synthesize request for "
                + f.url + ": " + e);
            return null;
        }
    }

    private static AuditIssueSeverity mapSeverity(String sev) {
        if (sev == null) return AuditIssueSeverity.INFORMATION;
        switch (sev.toUpperCase()) {
            case "CRITICAL":
            case "HIGH":   return AuditIssueSeverity.HIGH;
            case "MEDIUM": return AuditIssueSeverity.MEDIUM;
            case "LOW":    return AuditIssueSeverity.LOW;
            default:       return AuditIssueSeverity.INFORMATION;
        }
    }

    private static AuditIssueConfidence mapConfidence(String tier) {
        if ("INTERESTING".equalsIgnoreCase(tier)) return AuditIssueConfidence.FIRM;
        if ("COMMON".equalsIgnoreCase(tier))      return AuditIssueConfidence.TENTATIVE;
        return AuditIssueConfidence.TENTATIVE;
    }

    private static String safeShort(String s, int len) {
        if (s == null) return "";
        return s.length() <= len ? s : s.substring(0, len - 1) + "…";
    }

    private static String buildBackground(Finding f) {
        StringBuilder sb = new StringBuilder();
        if (f.description != null) sb.append(f.description);
        if (f.reason != null && !f.reason.isEmpty()) {
            if (sb.length() > 0) sb.append("\n\n");
            sb.append("Classifier rationale: ").append(f.reason);
        }
        return sb.toString();
    }

    private static String buildIssueDetail(Finding f) {
        StringBuilder sb = new StringBuilder();
        sb.append("Imported from HunterPy.\n");
        sb.append("Module: ").append(f.module).append("\n");
        sb.append("Type:   ").append(f.type).append("\n");
        if (f.score > 0) sb.append("Score:  ").append(f.score).append("\n");
        if (f.cvss > 0)  sb.append("CVSS:   ").append(f.cvss).append("\n");
        if (f.evidence != null && !f.evidence.isEmpty()) {
            sb.append("\nEvidence:\n");
            for (Map.Entry<String, Object> e : f.evidence.entrySet()) {
                sb.append("  ").append(e.getKey()).append(": ")
                  .append(e.getValue()).append("\n");
            }
        }
        return sb.toString();
    }

    private static String buildIssueRemediation(Finding f) {
        return f.remediation == null ? "" : f.remediation;
    }

    // ================================================================
    // Inner classes
    // ================================================================
    private static final class Finding {
        final String id, title, description, url, module, type, severity,
                     tier, reason, remediation;
        final double score, cvss, confidence;
        final Map<String, Object> evidence;
        Finding(String id, String title, String description, String url,
                String module, String type, String severity, String tier,
                String reason, String remediation, double score, double cvss,
                double confidence, Map<String, Object> evidence) {
            this.id = id; this.title = title; this.description = description;
            this.url = url; this.module = module; this.type = type;
            this.severity = severity; this.tier = tier; this.reason = reason;
            this.remediation = remediation; this.score = score; this.cvss = cvss;
            this.confidence = confidence; this.evidence = evidence;
        }
    }

    private static final class FindingsModel extends AbstractTableModel {
        static final int COL_TIER = 0, COL_SEVERITY = 1, COL_MODULE = 2,
                         COL_TITLE = 3, COL_URL = 4;
        private static final String[] COLS = {
            "Tier", "Severity", "Module", "Title", "URL"
        };

        private final List<Finding> master = new ArrayList<>();
        private final List<Finding> visible = new ArrayList<>();
        private String filter = "";

        void load(Object json) {
            master.clear();
            Map<String, Object> top = MiniJson.asMap(json);
            Object f = top.get("findings");
            if (f instanceof Map) {
                Map<String, Object> grouped = MiniJson.asMap(f);
                for (String t : new String[]{"INTERESTING", "COMMON", "FALSE_ALARM"}) {
                    for (Object o : MiniJson.asList(grouped.get(t))) addOne(o);
                }
            } else if (f instanceof List) {
                for (Object o : MiniJson.asList(f)) addOne(o);
            }
            applyFilter();
        }

        private void addOne(Object o) {
            Map<String, Object> m = MiniJson.asMap(o);
            String tier = MiniJson.asString(m.get("classification"),
                                  MiniJson.asString(m.get("tier"), "COMMON"));
            Finding f = new Finding(
                MiniJson.asString(m.get("id"), ""),
                MiniJson.asString(m.get("title"), ""),
                MiniJson.asString(m.getOrDefault("description",
                    m.getOrDefault("details", "")), ""),
                MiniJson.asString(m.get("url"), ""),
                MiniJson.asString(m.get("module"), ""),
                MiniJson.asString(m.get("type"), ""),
                MiniJson.asString(m.get("severity"), "INFO"),
                tier == null ? "COMMON" : tier.toUpperCase(),
                MiniJson.asString(m.get("classification_reason"), ""),
                stringOrSummary(m.get("remediation")),
                doubleOr(m.get("score"), 0),
                doubleOr(m.get("cvss"), 0),
                doubleOr(m.get("classification_confidence"), 0),
                MiniJson.asMap(m.get("evidence"))
            );
            master.add(f);
        }

        void setFilter(String s) {
            this.filter = s == null ? "" : s.trim().toLowerCase();
            applyFilter();
        }

        private void applyFilter() {
            visible.clear();
            for (Finding f : master) {
                if (filter.isEmpty() ||
                    (f.title + " " + f.url + " " + f.module).toLowerCase().contains(filter)) {
                    visible.add(f);
                }
            }
            fireTableDataChanged();
        }

        Finding findingAt(int rowIndex) { return visible.get(rowIndex); }
        List<Finding> visibleFindings() { return Collections.unmodifiableList(visible); }

        String detailText(int rowIndex) {
            Finding f = visible.get(rowIndex);
            StringBuilder sb = new StringBuilder();
            sb.append(f.tier).append("  ").append(f.severity).append("\n");
            sb.append(f.title).append("\n");
            sb.append(f.url).append("\n\n");
            if (f.description != null && !f.description.isEmpty()) {
                sb.append(f.description).append("\n\n");
            }
            if (f.reason != null && !f.reason.isEmpty()) {
                sb.append("Why flagged: ").append(f.reason)
                  .append(" (confidence ").append(Math.round(f.confidence*100)).append("%)\n\n");
            }
            if (f.remediation != null && !f.remediation.isEmpty()) {
                sb.append("Remediation:\n").append(f.remediation).append("\n\n");
            }
            if (f.evidence != null && !f.evidence.isEmpty()) {
                sb.append("Evidence:\n");
                for (Map.Entry<String, Object> e : f.evidence.entrySet()) {
                    sb.append("  ").append(e.getKey()).append(": ")
                      .append(e.getValue()).append("\n");
                }
            }
            return sb.toString();
        }

        @Override public int getRowCount()           { return visible.size(); }
        @Override public int getColumnCount()        { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }

        @Override
        public Object getValueAt(int row, int col) {
            Finding f = visible.get(row);
            switch (col) {
                case COL_TIER:     return f.tier;
                case COL_SEVERITY: return f.severity;
                case COL_MODULE:   return f.module;
                case COL_TITLE:    return f.title;
                case COL_URL:      return f.url;
                default:           return "";
            }
        }
    }

    private static String stringOrSummary(Object v) {
        if (v == null) return "";
        if (v instanceof Map) {
            return MiniJson.asString(MiniJson.asMap(v).get("summary"), v.toString());
        }
        return v.toString();
    }

    private static double doubleOr(Object v, double def) {
        if (v instanceof Number) return ((Number) v).doubleValue();
        try { return v == null ? def : Double.parseDouble(v.toString()); }
        catch (NumberFormatException e) { return def; }
    }

    /** Coloured severity cell — keeps Burp's L&F intact. */
    private static final class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v,
                boolean sel, boolean focus, int row, int col) {
            JLabel l = (JLabel) super.getTableCellRendererComponent(
                t, v, sel, focus, row, col);
            String s = String.valueOf(v).toUpperCase();
            Color fg;
            switch (s) {
                case "CRITICAL": fg = new Color(0xDC, 0x26, 0x26); break;
                case "HIGH":     fg = new Color(0xEA, 0x58, 0x0C); break;
                case "MEDIUM":   fg = new Color(0xD9, 0x77, 0x06); break;
                case "LOW":      fg = new Color(0x16, 0xA3, 0x4A); break;
                default:         fg = Color.GRAY;
            }
            if (!sel) l.setForeground(fg);
            l.setFont(l.getFont().deriveFont(Font.BOLD));
            return l;
        }
    }
}
