package io.hunterpy.gui;

import io.hunterpy.gui.ui.MainWindow;
import io.hunterpy.gui.ui.Theme;

import javax.swing.SwingUtilities;

/**
 * HunterPy GUI entry point.
 *
 * <p>Run:</p>
 * <pre>
 *   javac -d out $(find gui/java/src/main/java -name '*.java')
 *   java  -cp out io.hunterpy.gui.App  [path/to/report.json]
 * </pre>
 *
 * <p>If a CLI arg is provided, that report is loaded on launch; otherwise
 * the window opens empty and the user picks via File ▸ Open report….</p>
 */
public final class App {

    private App() { }

    public static void main(String[] args) {
        Theme.apply();
        SwingUtilities.invokeLater(() -> {
            MainWindow win = new MainWindow();
            win.setVisible(true);
            win.loadIfProvided(args);
        });
    }
}
