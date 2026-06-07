package io.hunterpy.gui.ui.widgets;

import io.hunterpy.gui.ui.Theme;

import javax.swing.JLabel;
import javax.swing.border.EmptyBorder;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/** Rounded coloured label — used for severity / tier badges in tables. */
public final class Pill extends JLabel {

    private final Color fill;

    public Pill(String text, Color fill) {
        super(text);
        this.fill = fill;
        setForeground(Color.WHITE);
        setFont(Theme.UI_BOLD.deriveFont(11f));
        setBorder(new EmptyBorder(2, 9, 2, 9));
        setOpaque(false);
        setPreferredSize(new Dimension(Math.max(60, getPreferredSize().width + 18), 22));
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                            RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(fill);
        g2.fillRoundRect(0, 0, getWidth(), getHeight(), 14, 14);
        g2.dispose();
        super.paintComponent(g);
    }
}
