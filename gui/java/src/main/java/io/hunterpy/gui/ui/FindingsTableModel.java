package io.hunterpy.gui.ui;

import io.hunterpy.gui.model.Finding;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Backing TableModel for the findings table.
 *
 * <p>Holds an unfiltered master list and a derived filtered list. Filter
 * changes call {@link #applyFilter} which fires a single
 * {@code fireTableDataChanged} — letting JTable repaint efficiently.
 */
public final class FindingsTableModel extends AbstractTableModel {

    public static final int COL_TIER     = 0;
    public static final int COL_SEVERITY = 1;
    public static final int COL_SCORE    = 2;
    public static final int COL_MODULE   = 3;
    public static final int COL_TITLE    = 4;
    public static final int COL_URL      = 5;

    private static final String[] COLS = {
        "Tier", "Severity", "Score", "Module", "Finding", "URL"
    };

    private final List<Finding> master = new ArrayList<>();
    private final List<Finding> visible = new ArrayList<>();

    private String searchText = "";
    private Finding.Tier tierFilter = null;
    private Finding.Severity severityFilter = null;
    private String moduleFilter = null;

    public void setData(List<Finding> findings) {
        master.clear();
        master.addAll(findings);
        applyFilter();
    }

    public Finding rowAt(int rowIndex) {
        return rowIndex >= 0 && rowIndex < visible.size()
                ? visible.get(rowIndex) : null;
    }

    public void setSearch(String s)                          { this.searchText = s == null ? "" : s.trim().toLowerCase(); applyFilter(); }
    public void setTierFilter(Finding.Tier t)                { this.tierFilter = t; applyFilter(); }
    public void setSeverityFilter(Finding.Severity s)        { this.severityFilter = s; applyFilter(); }
    public void setModuleFilter(String m)                    { this.moduleFilter = (m == null || m.isEmpty()) ? null : m; applyFilter(); }

    public int visibleCount() { return visible.size(); }
    public int masterCount()  { return master.size(); }

    private void applyFilter() {
        visible.clear();
        for (Finding f : master) {
            if (tierFilter != null && f.tier() != tierFilter) continue;
            if (severityFilter != null && f.severity() != severityFilter) continue;
            if (moduleFilter != null && !moduleFilter.equals(f.module())) continue;
            if (!searchText.isEmpty()) {
                String hay = (f.title() + " " + f.url() + " "
                              + f.module() + " " + f.description()).toLowerCase();
                if (!hay.contains(searchText)) continue;
            }
            visible.add(f);
        }
        fireTableDataChanged();
    }

    // ---------- TableModel ----------
    @Override public int getRowCount()                  { return visible.size(); }
    @Override public int getColumnCount()               { return COLS.length; }
    @Override public String getColumnName(int c)        { return COLS[c]; }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnIndex == COL_SCORE ? Double.class : Object.class;
    }

    @Override
    public Object getValueAt(int row, int col) {
        Finding f = visible.get(row);
        switch (col) {
            case COL_TIER:     return f.tier();
            case COL_SEVERITY: return f.severity();
            case COL_SCORE:    return f.score() > 0 ? f.score() : f.cvss();
            case COL_MODULE:   return f.module();
            case COL_TITLE:    return f.title();
            case COL_URL:      return f.url();
            default:           return "";
        }
    }
}
