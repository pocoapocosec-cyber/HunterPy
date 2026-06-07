package io.hunterpy.gui.ui;

import io.hunterpy.gui.model.Finding;

import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.plaf.ColorUIResource;
import javax.swing.plaf.FontUIResource;
import java.awt.Color;
import java.awt.Font;

/**
 * Centralised colours, fonts, and L&F bootstrapping.
 *
 * <p>We use the Nimbus L&F because it is bundled with every JDK 11+ and
 * looks acceptable on Linux/macOS/Windows without a third-party theme JAR.
 * Burp Suite ships its own dark theme using exactly this approach.
 */
public final class Theme {

    public static final Color BG_DEEP   = new Color(0x0B, 0x12, 0x20);
    public static final Color BG_PANEL  = new Color(0x1E, 0x29, 0x3B);
    public static final Color BG_ROW    = new Color(0x17, 0x20, 0x33);
    public static final Color BG_ROW_HI = new Color(0x24, 0x30, 0x49);
    public static final Color LINE      = new Color(0x33, 0x41, 0x55);
    public static final Color TEXT      = new Color(0xE5, 0xE7, 0xEB);
    public static final Color TEXT_DIM  = new Color(0x94, 0xA3, 0xB8);
    public static final Color BRAND     = new Color(0x06, 0xB6, 0xD4);

    public static final Color SEV_CRITICAL = new Color(0xDC, 0x26, 0x26);
    public static final Color SEV_HIGH     = new Color(0xEA, 0x58, 0x0C);
    public static final Color SEV_MEDIUM   = new Color(0xD9, 0x77, 0x06);
    public static final Color SEV_LOW      = new Color(0x16, 0xA3, 0x4A);
    public static final Color SEV_INFO     = new Color(0x6B, 0x72, 0x80);

    public static final Color TIER_INT  = SEV_CRITICAL;
    public static final Color TIER_COM  = SEV_MEDIUM;
    public static final Color TIER_FA   = SEV_LOW;

    public static final Font UI_FONT   = new Font(Font.SANS_SERIF, Font.PLAIN, 13);
    public static final Font UI_BOLD   = new Font(Font.SANS_SERIF, Font.BOLD,  13);
    public static final Font MONO      = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    public static final Font HEADER    = new Font(Font.SANS_SERIF, Font.BOLD,  18);

    private Theme() { }

    public static void apply() {
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException
                 | IllegalAccessException | UnsupportedLookAndFeelException ignored) {
            // Fall back to system L&F if Nimbus is unavailable.
        }

        // Dark-ify Nimbus
        UIManager.put("control",                new ColorUIResource(BG_PANEL));
        UIManager.put("info",                   new ColorUIResource(BG_PANEL));
        UIManager.put("nimbusBase",             new ColorUIResource(BG_DEEP));
        UIManager.put("nimbusAlertYellow",      new ColorUIResource(SEV_MEDIUM));
        UIManager.put("nimbusDisabledText",     new ColorUIResource(TEXT_DIM));
        UIManager.put("nimbusFocus",            new ColorUIResource(BRAND));
        UIManager.put("nimbusGreen",            new ColorUIResource(SEV_LOW));
        UIManager.put("nimbusInfoBlue",         new ColorUIResource(BRAND));
        UIManager.put("nimbusLightBackground",  new ColorUIResource(BG_PANEL));
        UIManager.put("nimbusOrange",           new ColorUIResource(SEV_HIGH));
        UIManager.put("nimbusRed",              new ColorUIResource(SEV_CRITICAL));
        UIManager.put("nimbusSelectedText",     new ColorUIResource(TEXT));
        UIManager.put("nimbusSelectionBackground", new ColorUIResource(BG_ROW_HI));
        UIManager.put("text",                   new ColorUIResource(TEXT));
        UIManager.put("Panel.background",       new ColorUIResource(BG_PANEL));
        UIManager.put("Label.foreground",       new ColorUIResource(TEXT));
        UIManager.put("Label.font",             new FontUIResource(UI_FONT));
        UIManager.put("Table.background",       new ColorUIResource(BG_PANEL));
        UIManager.put("Table.foreground",       new ColorUIResource(TEXT));
        UIManager.put("Table.gridColor",        new ColorUIResource(LINE));
        UIManager.put("Table.selectionBackground", new ColorUIResource(BG_ROW_HI));
        UIManager.put("Table.selectionForeground", new ColorUIResource(TEXT));
        UIManager.put("TableHeader.background", new ColorUIResource(BG_DEEP));
        UIManager.put("TableHeader.foreground", new ColorUIResource(BRAND));
        UIManager.put("TableHeader.font",       new FontUIResource(UI_BOLD));
        UIManager.put("TextField.background",   new ColorUIResource(BG_DEEP));
        UIManager.put("TextField.foreground",   new ColorUIResource(TEXT));
        UIManager.put("TextField.caretForeground", new ColorUIResource(BRAND));
        UIManager.put("TextArea.background",    new ColorUIResource(BG_DEEP));
        UIManager.put("TextArea.foreground",    new ColorUIResource(TEXT));
        UIManager.put("EditorPane.background",  new ColorUIResource(BG_DEEP));
        UIManager.put("EditorPane.foreground",  new ColorUIResource(TEXT));
        UIManager.put("TabbedPane.background",  new ColorUIResource(BG_PANEL));
        UIManager.put("TabbedPane.foreground",  new ColorUIResource(TEXT));
        UIManager.put("TabbedPane.contentAreaColor", new ColorUIResource(BG_PANEL));
        UIManager.put("ScrollPane.background",  new ColorUIResource(BG_PANEL));
        UIManager.put("ScrollBar.background",   new ColorUIResource(BG_DEEP));
        UIManager.put("ScrollBar.thumb",        new ColorUIResource(LINE));
        UIManager.put("Tree.background",        new ColorUIResource(BG_PANEL));
        UIManager.put("Tree.foreground",        new ColorUIResource(TEXT));
        UIManager.put("Tree.selectionBackground", new ColorUIResource(BG_ROW_HI));
        UIManager.put("ComboBox.background",    new ColorUIResource(BG_DEEP));
        UIManager.put("ComboBox.foreground",    new ColorUIResource(TEXT));
        UIManager.put("Button.background",      new ColorUIResource(BG_DEEP));
        UIManager.put("Button.foreground",      new ColorUIResource(TEXT));
        UIManager.put("MenuBar.background",     new ColorUIResource(BG_DEEP));
        UIManager.put("MenuBar.foreground",     new ColorUIResource(TEXT));
        UIManager.put("Menu.background",        new ColorUIResource(BG_DEEP));
        UIManager.put("Menu.foreground",        new ColorUIResource(TEXT));
        UIManager.put("MenuItem.background",    new ColorUIResource(BG_PANEL));
        UIManager.put("MenuItem.foreground",    new ColorUIResource(TEXT));
        UIManager.put("PopupMenu.background",   new ColorUIResource(BG_PANEL));
        UIManager.put("ToolTip.background",     new ColorUIResource(BG_DEEP));
        UIManager.put("ToolTip.foreground",     new ColorUIResource(TEXT));
        UIManager.put("Separator.foreground",   new ColorUIResource(LINE));
        UIManager.put("Viewport.background",    new ColorUIResource(BG_PANEL));
    }

    public static Color colorFor(Finding.Severity s) {
        switch (s) {
            case CRITICAL: return SEV_CRITICAL;
            case HIGH:     return SEV_HIGH;
            case MEDIUM:   return SEV_MEDIUM;
            case LOW:      return SEV_LOW;
            default:       return SEV_INFO;
        }
    }

    public static Color colorFor(Finding.Tier t) {
        switch (t) {
            case INTERESTING: return TIER_INT;
            case COMMON:      return TIER_COM;
            case FALSE_ALARM: return TIER_FA;
            default:          return SEV_INFO;
        }
    }
}
