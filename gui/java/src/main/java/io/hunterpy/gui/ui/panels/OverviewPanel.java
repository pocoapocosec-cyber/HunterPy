package io.hunterpy.gui.ui.panels;

import io.hunterpy.gui.model.Finding;
import io.hunterpy.gui.model.ScanReport;
import io.hunterpy.gui.ui.Theme;
import io.hunterpy.gui.ui.widgets.DonutChart;
import io.hunterpy.gui.ui.widgets.StatCard;
import io.hunterpy.gui.util.Json;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** First tab: at-a-glance dashboard with stat cards, donut chart, chains, summary. */
public final class OverviewPanel extends JPanel {

    private final JPanel statCardsRow;
    private final DonutChart severityDonut;
    private final DonutChart tierDonut;
    private final JPanel chainsBox;
    private final JPanel summaryBox;
    private final JLabel metaLabel;

    public OverviewPanel() {
        super(new BorderLayout());
        setBackground(Theme.BG_PANEL);
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBackground(Theme.BG_PANEL);

        metaLabel = new JLabel(" ");
        metaLabel.setForeground(Theme.TEXT_DIM);
        metaLabel.setFont(Theme.UI_FONT.deriveFont(12f));
        metaLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        root.add(metaLabel);
        root.add(Box.createVerticalStrut(12));

        statCardsRow = new JPanel(new GridLayout(1, 5, 12, 0));
        statCardsRow.setOpaque(false);
        statCardsRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 100));
        statCardsRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        root.add(statCardsRow);
        root.add(Box.createVerticalStrut(18));

        JPanel charts = new JPanel(new GridLayout(1, 2, 18, 0));
        charts.setOpaque(false);
        charts.setMaximumSize(new Dimension(Integer.MAX_VALUE, 260));
        charts.setAlignmentX(Component.LEFT_ALIGNMENT);

        severityDonut = new DonutChart();
        tierDonut     = new DonutChart();
        charts.add(donutCard("Severity distribution", severityDonut));
        charts.add(donutCard("Tier distribution",     tierDonut));
        root.add(charts);
        root.add(Box.createVerticalStrut(18));

        summaryBox = sectionBox("Notable findings");
        root.add(summaryBox);
        root.add(Box.createVerticalStrut(14));

        chainsBox  = sectionBox("Cross-finding attack chains");
        root.add(chainsBox);
        root.add(Box.createVerticalGlue());

        JScrollPane sp = new JScrollPane(root);
        sp.setBorder(null);
        sp.getViewport().setBackground(Theme.BG_PANEL);
        add(sp, BorderLayout.CENTER);
    }

    public void load(ScanReport r) {
        metaLabel.setText("<html><b>Target:</b> " + esc(r.target())
            + " &nbsp; <b>Mode:</b> " + esc(r.mode())
            + " &nbsp; <b>Duration:</b> " + esc(r.duration())
            + " &nbsp; <b>Modules:</b> " + esc(String.join(", ", r.modulesRun()))
            + "</html>");

        // Stat cards
        Map<Finding.Tier, Integer> tiers = r.tierCounts();
        Map<Finding.Severity, Integer> sevs = r.severityCounts();
        statCardsRow.removeAll();
        statCardsRow.add(stat("Total",        r.findings().size(),   Theme.BRAND));
        statCardsRow.add(stat("Interesting",  tiers.get(Finding.Tier.INTERESTING),  Theme.TIER_INT));
        statCardsRow.add(stat("Common",       tiers.get(Finding.Tier.COMMON),       Theme.TIER_COM));
        statCardsRow.add(stat("False alarm",  tiers.get(Finding.Tier.FALSE_ALARM),  Theme.TIER_FA));
        statCardsRow.add(stat("Critical+High", sevs.get(Finding.Severity.CRITICAL)
                                              + sevs.get(Finding.Severity.HIGH), Theme.SEV_HIGH));

        // Donuts
        Map<String, DonutChart.Slice> sevSlices = new LinkedHashMap<>();
        sevSlices.put("CRITICAL", new DonutChart.Slice(sevs.get(Finding.Severity.CRITICAL), Theme.SEV_CRITICAL));
        sevSlices.put("HIGH",     new DonutChart.Slice(sevs.get(Finding.Severity.HIGH),     Theme.SEV_HIGH));
        sevSlices.put("MEDIUM",   new DonutChart.Slice(sevs.get(Finding.Severity.MEDIUM),   Theme.SEV_MEDIUM));
        sevSlices.put("LOW",      new DonutChart.Slice(sevs.get(Finding.Severity.LOW),      Theme.SEV_LOW));
        sevSlices.put("INFO",     new DonutChart.Slice(sevs.get(Finding.Severity.INFO),     Theme.SEV_INFO));
        severityDonut.setSlices(sevSlices);
        severityDonut.setCenterLabel("by severity");

        Map<String, DonutChart.Slice> tierSlices = new LinkedHashMap<>();
        tierSlices.put("INT", new DonutChart.Slice(tiers.get(Finding.Tier.INTERESTING), Theme.TIER_INT));
        tierSlices.put("COM", new DonutChart.Slice(tiers.get(Finding.Tier.COMMON),      Theme.TIER_COM));
        tierSlices.put("FA",  new DonutChart.Slice(tiers.get(Finding.Tier.FALSE_ALARM), Theme.TIER_FA));
        tierDonut.setSlices(tierSlices);
        tierDonut.setCenterLabel("by tier");

        // Notable bullets
        replaceBody(summaryBox, bulletList(r.findingsSummary()));

        // Chains
        replaceBody(chainsBox, chainCards(r.attackChains()));

        revalidate();
        repaint();
    }

    // ---------- helpers ----------
    private static StatCard stat(String label, Integer value, Color color) {
        StatCard c = new StatCard(label, color);
        c.setValue(value == null ? 0 : value);
        return c;
    }

    private static JPanel donutCard(String title, DonutChart chart) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(Theme.BG_PANEL);
        p.setBorder(BorderFactory.createLineBorder(Theme.LINE));
        JLabel t = new JLabel("  " + title);
        t.setFont(Theme.UI_BOLD); t.setForeground(Theme.BRAND);
        t.setBorder(BorderFactory.createEmptyBorder(8, 0, 0, 0));
        p.add(t, BorderLayout.NORTH);
        p.add(chart, BorderLayout.CENTER);
        return p;
    }

    private static JPanel sectionBox(String title) {
        JPanel p = new JPanel();
        p.setLayout(new BorderLayout());
        p.setOpaque(false);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel t = new JLabel(title.toUpperCase());
        t.setForeground(Theme.BRAND);
        t.setFont(Theme.UI_BOLD.deriveFont(11f));
        t.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));

        JPanel north = new JPanel(new BorderLayout());
        north.setOpaque(false);
        north.add(t, BorderLayout.NORTH);
        JSeparator sep = new JSeparator();
        sep.setForeground(Theme.LINE);
        north.add(sep, BorderLayout.SOUTH);

        p.add(north, BorderLayout.NORTH);
        p.add(emptyBody(), BorderLayout.CENTER);
        return p;
    }

    private static JPanel emptyBody() {
        JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setOpaque(false);
        return body;
    }

    private static void replaceBody(JPanel section, JPanel body) {
        section.remove(((BorderLayout) section.getLayout()).getLayoutComponent(BorderLayout.CENTER));
        section.add(body, BorderLayout.CENTER);
    }

    private static JPanel bulletList(List<String> lines) {
        JPanel body = emptyBody();
        body.setBorder(BorderFactory.createEmptyBorder(6, 0, 0, 0));
        if (lines == null || lines.isEmpty()) {
            JLabel l = new JLabel("None.");
            l.setForeground(Theme.TEXT_DIM);
            body.add(l);
            return body;
        }
        for (String s : lines) {
            JLabel l = new JLabel("• " + s);
            l.setForeground(Theme.TEXT);
            l.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
            body.add(l);
        }
        return body;
    }

    private static JPanel chainCards(List<Map<String, Object>> chains) {
        JPanel body = emptyBody();
        body.setBorder(BorderFactory.createEmptyBorder(6, 0, 0, 0));
        if (chains == null || chains.isEmpty()) {
            JLabel l = new JLabel("No chains detected.");
            l.setForeground(Theme.TEXT_DIM);
            body.add(l);
            return body;
        }
        for (Map<String, Object> c : chains) {
            JPanel card = new JPanel(new BorderLayout());
            card.setBackground(new Color(0x3D, 0x08, 0x08));
            card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Theme.SEV_CRITICAL),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)));
            card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));
            card.setAlignmentX(Component.LEFT_ALIGNMENT);

            JLabel title = new JLabel(Json.asString(c.get("title"), "chain"));
            title.setForeground(new Color(0xFC, 0xA5, 0xA5));
            title.setFont(Theme.UI_BOLD);
            card.add(title, BorderLayout.NORTH);

            JLabel desc = new JLabel(Json.asString(c.get("details"), ""));
            desc.setForeground(Theme.TEXT);
            card.add(desc, BorderLayout.CENTER);

            body.add(card);
            body.add(Box.createVerticalStrut(6));
        }
        return body;
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
