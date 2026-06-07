package io.hunterpy.gui.ui;

import io.hunterpy.gui.io.ReportLoader;
import io.hunterpy.gui.model.ScanReport;
import io.hunterpy.gui.ui.panels.DorksPanel;
import io.hunterpy.gui.ui.panels.FindingsPanel;
import io.hunterpy.gui.ui.panels.OverviewPanel;
import io.hunterpy.gui.ui.panels.TargetPanel;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.KeyEvent;
import java.awt.Toolkit;
import java.awt.event.InputEvent;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * Top-level application window. Holds the tabbed view + menu/toolbar.
 *
 * <p>This class is intentionally I/O-light: it loads JSON reports via
 * {@link ReportLoader} on a background worker, but it never starts a
 * scan, talks to the network, or invokes external tools. Scanning is
 * the Python CLI's job — this GUI is a viewer / triage console.
 */
public final class MainWindow extends JFrame {

    private final OverviewPanel overview = new OverviewPanel();
    private final FindingsPanel findings = new FindingsPanel();
    private final TargetPanel target     = new TargetPanel();
    private final DorksPanel dorks       = new DorksPanel();
    private final JTabbedPane tabs       = new JTabbedPane();
    private final JLabel statusBar       = new JLabel(" Ready.");
    private ScanReport currentReport;

    public MainWindow() {
        super("HunterPy — Security Findings Console");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(new Dimension(1280, 800));
        setMinimumSize(new Dimension(960, 640));
        setLocationRelativeTo(null);

        tabs.addTab("Overview", overview);
        tabs.addTab("Findings", findings);
        tabs.addTab("Target",   target);
        tabs.addTab("Dorks",    dorks);

        statusBar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Theme.LINE));
        statusBar.setForeground(Theme.TEXT_DIM);

        setLayout(new BorderLayout());
        add(buildToolbar(), BorderLayout.NORTH);
        add(tabs,           BorderLayout.CENTER);
        add(statusBar,      BorderLayout.SOUTH);

        setJMenuBar(buildMenuBar());
    }

    // ---------- menu / toolbar ----------
    private JMenuBar buildMenuBar() {
        JMenuBar bar = new JMenuBar();

        JMenu file = new JMenu("File");
        JMenuItem open = new JMenuItem("Open report…");
        open.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_O,
            Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
        open.addActionListener(e -> openReportDialog());

        JMenuItem sample = new JMenuItem("Open bundled sample report");
        sample.addActionListener(e -> openSample());

        JMenuItem quit = new JMenuItem("Quit");
        quit.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_Q,
            Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()));
        quit.addActionListener(e -> dispatchEvent(new java.awt.event.WindowEvent(
            this, java.awt.event.WindowEvent.WINDOW_CLOSING)));

        file.add(open); file.add(sample); file.addSeparator(); file.add(quit);

        JMenu view = new JMenu("View");
        for (int i = 0; i < tabs.getTabCount(); i++) {
            final int idx = i;
            JMenuItem mi = new JMenuItem("Go to: " + tabs.getTitleAt(i));
            mi.setAccelerator(KeyStroke.getKeyStroke(
                KeyEvent.VK_1 + idx, InputEvent.ALT_DOWN_MASK));
            mi.addActionListener(e -> tabs.setSelectedIndex(idx));
            view.add(mi);
        }

        JMenu help = new JMenu("Help");
        JMenuItem about = new JMenuItem("About HunterPy GUI");
        about.addActionListener(e -> showAbout());
        help.add(about);

        bar.add(file); bar.add(view); bar.add(help);
        return bar;
    }

    private JToolBar buildToolbar() {
        JToolBar tb = new JToolBar();
        tb.setFloatable(false);
        tb.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Theme.LINE));

        JButton open = new JButton("Open report…");
        open.addActionListener(e -> openReportDialog());

        JButton sample = new JButton("Load sample");
        sample.addActionListener(e -> openSample());

        tb.add(open);
        tb.add(sample);
        tb.add(Box.createHorizontalGlue());

        JLabel disclaim = new JLabel("For authorized testing only ");
        disclaim.setForeground(Theme.SEV_MEDIUM);
        tb.add(disclaim);
        return tb;
    }

    // ---------- actions ----------
    private void openReportDialog() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Open HunterPy JSON report");
        chooser.setFileFilter(new FileNameExtensionFilter("HunterPy report (*.json)", "json"));
        File defaultDir = new File("output");
        if (defaultDir.isDirectory()) chooser.setCurrentDirectory(defaultDir);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            loadReport(chooser.getSelectedFile().toPath());
        }
    }

    private void openSample() {
        Optional<Path> sample = findSample();
        if (sample.isPresent()) {
            loadReport(sample.get());
        } else {
            JOptionPane.showMessageDialog(this,
                "No bundled sample found. Run a scan first:\n"
                + "  python main.py -t example.com --mode passive "
                + "--confirm-authorized --no-nvd\n"
                + "Then File ▸ Open report…",
                "No sample available",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /** Look for a sample in (1) ./samples (2) ../../samples (3) ../../../samples. */
    private Optional<Path> findSample() {
        String[] candidates = {
            "samples/sample_scan.json",
            "../../samples/sample_scan.json",
            "../../../samples/sample_scan.json",
        };
        for (String c : candidates) {
            Path p = Paths.get(c);
            if (p.toFile().isFile()) return Optional.of(p.toAbsolutePath());
        }
        return Optional.empty();
    }

    private void loadReport(Path path) {
        statusBar.setText("  Loading " + path + " …");
        SwingWorker<ScanReport, Void> worker = new SwingWorker<>() {
            @Override protected ScanReport doInBackground() throws IOException {
                return ReportLoader.load(path);
            }
            @Override protected void done() {
                try {
                    ScanReport report = get();
                    currentReport = report;
                    overview.load(report);
                    findings.load(report);
                    target.load(report);
                    dorks.load(report);
                    setTitle("HunterPy — " + report.target() + " — "
                             + report.findings().size() + " findings");
                    statusBar.setText("  Loaded " + report.findings().size()
                        + " findings from " + path);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(MainWindow.this,
                        "Failed to load report:\n" + ex.getMessage(),
                        "Load error", JOptionPane.ERROR_MESSAGE);
                    statusBar.setText("  Error.");
                }
            }
        };
        worker.execute();
    }

    private void showAbout() {
        JOptionPane.showMessageDialog(this,
            "HunterPy Java GUI v2.0\n\n"
            + "JSON-report viewer / triage console for HunterPy scans.\n"
            + "Loads reports produced by `python main.py … --format json`.\n\n"
            + "This GUI does NOT scan, exploit, or contact networks.\n"
            + "All scanning happens via the Python CLI; this is read-only.\n\n"
            + "Licensed under BUSL-1.1 — see LICENSE.",
            "About HunterPy GUI", JOptionPane.INFORMATION_MESSAGE);
    }

    public void loadIfProvided(String[] cliArgs) {
        if (cliArgs == null || cliArgs.length == 0) return;
        Path p = Paths.get(cliArgs[0]);
        if (p.toFile().isFile()) loadReport(p);
    }
}
