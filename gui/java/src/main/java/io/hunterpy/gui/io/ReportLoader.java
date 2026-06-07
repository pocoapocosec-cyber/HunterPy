package io.hunterpy.gui.io;

import io.hunterpy.gui.model.ScanReport;
import io.hunterpy.gui.util.Json;

import java.io.IOException;
import java.nio.file.Path;

/** Stateless file-system bridge between disk and the {@link ScanReport} model. */
public final class ReportLoader {

    private ReportLoader() { }

    public static ScanReport load(Path path) throws IOException {
        Object root = Json.parseFile(path);
        if (root == null) {
            throw new IOException("empty or invalid JSON in " + path);
        }
        return ScanReport.fromJson(root);
    }
}
