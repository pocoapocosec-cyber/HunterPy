package io.hunterpy.gui.ui.panels;

import io.hunterpy.gui.model.Finding;
import io.hunterpy.gui.model.ScanReport;
import io.hunterpy.gui.ui.FindingDetailPanel;
import io.hunterpy.gui.ui.FindingsTableModel;
import io.hunterpy.gui.ui.Theme;
import io.hunterpy.gui.ui.widgets.Pill;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SwingConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.Comparator;
import java.util.List;

/** Findings tab: filterable + sortable table on left, detail pane on right. */
public final class FindingsPanel extends JPanel {

    private final FindingsTableModel model = new FindingsTableModel();
    private final JTable table;
    private final FindingDetailPanel detail = new FindingDetailPanel();
    private final JLabel counter = new JLabel(" 0 findings ");
    private final JComboBox<Object> tierCombo;
    private final JComboBox<Object> sevCombo;
    private final JComboBox<Object> moduleCombo;
    private ScanReport currentReport;

    public FindingsPanel() {
        super(new BorderLayout());
        setBackground(Theme.BG_PANEL);

        table = new JTable(model);
        table.setRowHeight(28);
        table.setShowGrid(false);
        table.setIntercellSpacing(new java.awt.Dimension(0, 0));
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setFillsViewportHeight(true);
        table.setAutoCreateRowSorter(false);

        TableRowSorter<FindingsTableModel> sorter = new TableRowSorter<>(model);
        sorter.setComparator(FindingsTableModel.COL_TIER, Comparator.comparingInt(
            o -> ((Finding.Tier) o).ordinal()));
        sorter.setComparator(FindingsTableModel.COL_SEVERITY, Comparator.comparingInt(
            o -> -((Finding.Severity) o).rank()));
        sorter.toggleSortOrder(FindingsTableModel.COL_SCORE);
        sorter.setSortKeys(List.of(new RowSorter.SortKey(
            FindingsTableModel.COL_SCORE, SortOrder.DESCENDING)));
        table.setRowSorter(sorter);

        // Custom renderers
        TableColumn tierCol = table.getColumnModel().getColumn(FindingsTableModel.COL_TIER);
        tierCol.setCellRenderer(new PillRenderer(true));
        tierCol.setMaxWidth(140); tierCol.setMinWidth(120);

        TableColumn sevCol = table.getColumnModel().getColumn(FindingsTableModel.COL_SEVERITY);
        sevCol.setCellRenderer(new PillRenderer(false));
        sevCol.setMaxWidth(110); sevCol.setMinWidth(90);

        TableColumn scoreCol = table.getColumnModel().getColumn(FindingsTableModel.COL_SCORE);
        scoreCol.setCellRenderer(new ScoreRenderer());
        scoreCol.setMaxWidth(70);

        TableColumn modCol = table.getColumnModel().getColumn(FindingsTableModel.COL_MODULE);
        modCol.setMaxWidth(140); modCol.setMinWidth(90);

        TableColumn urlCol = table.getColumnModel().getColumn(FindingsTableModel.COL_URL);
        urlCol.setCellRenderer(new MutedRenderer());
        urlCol.setPreferredWidth(220);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row >= 0) {
                    int modelRow = table.convertRowIndexToModel(row);
                    detail.show(model.rowAt(modelRow), currentReport);
                }
            }
        });

        // Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 8));
        toolbar.setBackground(Theme.BG_PANEL);

        JTextField search = new JTextField(28);
        search.putClientProperty("JTextField.placeholderText", "Search…");
        search.getDocument().addDocumentListener(new DocumentListener() {
            void update() { model.setSearch(search.getText()); refreshCounter(); }
            @Override public void insertUpdate(DocumentEvent e) { update(); }
            @Override public void removeUpdate(DocumentEvent e) { update(); }
            @Override public void changedUpdate(DocumentEvent e) { update(); }
        });
        toolbar.add(new JLabel("Search"));
        toolbar.add(search);

        tierCombo = combo("Tier", "All", (Object[]) Finding.Tier.values());
        tierCombo.addActionListener(e -> {
            Object sel = tierCombo.getSelectedItem();
            model.setTierFilter(sel instanceof Finding.Tier ? (Finding.Tier) sel : null);
            refreshCounter();
        });
        toolbar.add(tierCombo);

        sevCombo = combo("Severity", "All", (Object[]) Finding.Severity.values());
        sevCombo.addActionListener(e -> {
            Object sel = sevCombo.getSelectedItem();
            model.setSeverityFilter(sel instanceof Finding.Severity ? (Finding.Severity) sel : null);
            refreshCounter();
        });
        toolbar.add(sevCombo);

        moduleCombo = combo("Module", "All");
        moduleCombo.addActionListener(e -> {
            Object sel = moduleCombo.getSelectedItem();
            model.setModuleFilter("All".equals(sel) ? null : String.valueOf(sel));
            refreshCounter();
        });
        toolbar.add(moduleCombo);

        toolbar.add(Box.createHorizontalStrut(20));
        counter.setForeground(Theme.TEXT_DIM);
        toolbar.add(counter);

        // Layout
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.getViewport().setBackground(Theme.BG_PANEL);
        tableScroll.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, Theme.LINE));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScroll, detail);
        split.setBorder(null);
        split.setDividerLocation(720);
        split.setResizeWeight(0.55);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        // Keyboard: open URL of selected row with Ctrl+Enter
        table.addKeyListener(new KeyAdapter() {
            @Override public void keyPressed(KeyEvent e) {
                if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_ENTER) {
                    int row = table.getSelectedRow();
                    if (row >= 0) {
                        Finding f = model.rowAt(table.convertRowIndexToModel(row));
                        if (f != null && f.url() != null && !f.url().isEmpty()) {
                            try {
                                java.awt.Desktop.getDesktop().browse(java.net.URI.create(f.url()));
                            } catch (Exception ignored) { }
                        }
                    }
                }
            }
        });
    }

    public void load(ScanReport report) {
        this.currentReport = report;
        model.setData(report.findings());

        // Populate module combo from observed modules
        DefaultComboBoxModel<Object> m = new DefaultComboBoxModel<>();
        m.addElement("All");
        for (String mod : report.modulesObserved()) m.addElement(mod);
        moduleCombo.setModel(m);

        if (model.getRowCount() > 0) {
            table.setRowSelectionInterval(0, 0);
        }
        refreshCounter();
    }

    private void refreshCounter() {
        counter.setText(String.format(" %d of %d findings ",
            model.visibleCount(), model.masterCount()));
    }

    private static JComboBox<Object> combo(String label, String allLabel, Object... items) {
        DefaultComboBoxModel<Object> m = new DefaultComboBoxModel<>();
        m.addElement(allLabel);
        for (Object i : items) m.addElement(i);
        JComboBox<Object> c = new JComboBox<>(m);
        c.setPrototypeDisplayValue("XXXXXXXXXX");
        return c;
    }

    // ---------- renderers ----------
    private static final class PillRenderer extends DefaultTableCellRenderer {
        private final boolean isTier;
        PillRenderer(boolean isTier) { this.isTier = isTier; }

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v,
                boolean sel, boolean focus, int row, int col) {
            JPanel wrap = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 3));
            wrap.setOpaque(true);
            wrap.setBackground(sel ? Theme.BG_ROW_HI : (row % 2 == 0 ? Theme.BG_PANEL : Theme.BG_ROW));
            if (v == null) return wrap;
            Color c = isTier
                ? Theme.colorFor((Finding.Tier) v)
                : Theme.colorFor((Finding.Severity) v);
            wrap.add(new Pill(v.toString(), c));
            return wrap;
        }
    }

    private static final class ScoreRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v,
                boolean sel, boolean focus, int row, int col) {
            JLabel l = (JLabel) super.getTableCellRendererComponent(
                t, v, sel, focus, row, col);
            l.setHorizontalAlignment(SwingConstants.RIGHT);
            l.setFont(Theme.MONO);
            l.setForeground(sel ? Theme.TEXT : Theme.TEXT);
            l.setBackground(sel ? Theme.BG_ROW_HI : (row % 2 == 0 ? Theme.BG_PANEL : Theme.BG_ROW));
            if (v instanceof Number) {
                double d = ((Number) v).doubleValue();
                l.setText(d == 0 ? "—" : String.format("%.1f", d));
            }
            return l;
        }
    }

    private static final class MutedRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable t, Object v,
                boolean sel, boolean focus, int row, int col) {
            JLabel l = (JLabel) super.getTableCellRendererComponent(
                t, v, sel, focus, row, col);
            l.setForeground(Theme.TEXT_DIM);
            l.setFont(Theme.MONO.deriveFont(11f));
            l.setBackground(sel ? Theme.BG_ROW_HI : (row % 2 == 0 ? Theme.BG_PANEL : Theme.BG_ROW));
            return l;
        }
    }
}
