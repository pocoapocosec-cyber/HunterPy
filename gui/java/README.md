# HunterPy Java GUI

Desktop **findings console** for HunterPy. Read-only by design — opens
JSON reports produced by the Python CLI and lets you triage them.

## Why Java + Swing?

Pentesters already have a JDK installed (for Burp Suite). Shipping a
GUI as a single JAR with no Maven/Gradle/Electron download is the path
of least friction for them. We use stdlib Swing — no JavaFX, no
third-party look-and-feel JAR, no Jackson — so the whole build is one
`javac` invocation.

## Build & run

```bash
cd gui/java
./build.sh
# → out/  (.class files)
# → HunterPyGUI.jar  (if the `jar` tool is on PATH)

# Launch with a report:
java -cp out io.hunterpy.gui.App ../../output/example.com_*.json

# Or open the bundled sample via File ▸ Open bundled sample report
java -cp out io.hunterpy.gui.App

# If a JAR was built:
java -jar HunterPyGUI.jar  ../../output/example.com_*.json
```

Requires JDK 11 or newer (`javac --release 11`).

## What it does

| Tab          | Shows                                                                |
|--------------|----------------------------------------------------------------------|
| **Overview** | Stat cards · severity + tier donut charts · attack chains · summary  |
| **Findings** | Sortable / filterable table → row click reveals PoC + impact + refs  |
| **Target**   | DNS records · WHOIS · behavioral baseline                            |
| **Dorks**    | Google-search URLs grouped by template (clickable, opens browser)    |

## What it does NOT do

- No scanning. The GUI never makes network calls; all scanning happens
  via `python main.py`.
- No exploit execution. The "Verification (proof of concept)" panel is
  copy-paste curl text, not a runner.
- No database writes. Reports are read-only inputs.

## Architecture

```
src/main/java/io/hunterpy/gui/
├── App.java                    entry point
├── SmokeTest.java              headless tests (16 assertions)
├── util/Json.java              ~200-line dependency-free JSON parser
├── model/
│   ├── Finding.java            severity + tier enums, immutable record
│   └── ScanReport.java         loads + derives counts; PoC/impact lookup
├── io/ReportLoader.java        Path → ScanReport
├── ui/
│   ├── Theme.java              Nimbus L&F + dark palette
│   ├── MainWindow.java         menu, toolbar, tabs, status bar
│   ├── FindingsTableModel.java filterable AbstractTableModel
│   ├── FindingDetailPanel.java HTML-rendered right pane
│   ├── widgets/                Pill · StatCard · DonutChart
│   └── panels/                 OverviewPanel · FindingsPanel · TargetPanel · DorksPanel
```

## Testing

`./build.sh` runs `SmokeTest` automatically — it exercises the JSON
parser, the model accessors, and loads the bundled sample report. CI
should fail the build on a non-zero exit from that step.
