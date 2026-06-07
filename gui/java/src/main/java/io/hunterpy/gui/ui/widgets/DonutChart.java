package io.hunterpy.gui.ui.widgets;

import io.hunterpy.gui.ui.Theme;

import javax.swing.JPanel;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Arc2D;
import java.util.LinkedHashMap;
import java.util.Map;

/** Pure-Swing donut chart — no dependencies, no Recharts equivalent needed. */
public final class DonutChart extends JPanel {

    private Map<String, Slice> slices = new LinkedHashMap<>();
    private String centerLabel = "";

    public static final class Slice {
        final int value;
        final Color color;
        public Slice(int value, Color color) {
            this.value = value;
            this.color = color;
        }
    }

    public DonutChart() {
        setOpaque(false);
        setPreferredSize(new Dimension(220, 220));
    }

    public void setSlices(Map<String, Slice> slices) {
        this.slices = slices;
        repaint();
    }

    public void setCenterLabel(String s) {
        this.centerLabel = s;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                            RenderingHints.VALUE_ANTIALIAS_ON);

        int total = slices.values().stream().mapToInt(s -> s.value).sum();
        int size = Math.min(getWidth(), getHeight()) - 12;
        int x = (getWidth() - size) / 2;
        int y = (getHeight() - size) / 2;

        if (total == 0) {
            g2.setColor(Theme.LINE);
            g2.setStroke(new BasicStroke(24f));
            g2.drawOval(x + 12, y + 12, size - 24, size - 24);
        } else {
            double start = 90.0;
            for (Slice s : slices.values()) {
                if (s.value == 0) continue;
                double extent = -360.0 * s.value / total;
                g2.setColor(s.color);
                g2.setStroke(new BasicStroke(28f, BasicStroke.CAP_BUTT,
                                             BasicStroke.JOIN_MITER));
                g2.draw(new Arc2D.Double(x + 14, y + 14, size - 28, size - 28,
                                         start, extent, Arc2D.OPEN));
                start += extent;
            }
        }

        // Center number
        g2.setColor(Theme.TEXT);
        g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 28));
        String txt = String.valueOf(total);
        FontMetrics fm = g2.getFontMetrics();
        g2.drawString(txt,
            (getWidth() - fm.stringWidth(txt)) / 2,
            getHeight() / 2 + fm.getAscent() / 2 - 6);

        g2.setColor(Theme.TEXT_DIM);
        g2.setFont(Theme.UI_FONT.deriveFont(11f));
        FontMetrics fm2 = g2.getFontMetrics();
        g2.drawString(centerLabel,
            (getWidth() - fm2.stringWidth(centerLabel)) / 2,
            getHeight() / 2 + fm.getAscent() / 2 + 12);

        g2.dispose();
    }
}
