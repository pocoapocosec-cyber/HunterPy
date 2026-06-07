package io.hunterpy.gui.ui.widgets;

import io.hunterpy.gui.ui.Theme;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;

/** "Big-number" stat card used on the overview dashboard. */
public final class StatCard extends JPanel {

    private final JLabel valueLabel;
    private final JLabel labelLabel;

    public StatCard(String label, Color accent) {
        super(new BorderLayout());
        setBackground(Theme.BG_PANEL);
        setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(accent, 1, true),
            BorderFactory.createEmptyBorder(12, 16, 12, 16)));
        setPreferredSize(new Dimension(150, 80));

        valueLabel = new JLabel("0", SwingConstants.LEFT);
        valueLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 28));
        valueLabel.setForeground(accent);

        labelLabel = new JLabel(label.toUpperCase(), SwingConstants.LEFT);
        labelLabel.setFont(Theme.UI_FONT.deriveFont(10f));
        labelLabel.setForeground(Theme.TEXT_DIM);

        add(valueLabel, BorderLayout.CENTER);
        add(labelLabel, BorderLayout.SOUTH);
    }

    public void setValue(int n) {
        valueLabel.setText(String.valueOf(n));
    }
}
