# HunterPy ↔ Burp Suite extension

Adds a **HunterPy** tab inside Burp Suite that imports a HunterPy JSON
report and lets you:

- Review findings in a sortable, filterable table
- Send the URL of any finding to **Repeater** with one click
- Add visible findings to the **Site Map** as synthetic GET requests
- **Emit Burp audit issues** so HunterPy findings live alongside Burp's
  own scanner output in the Issues view

The extension is read-only — it never scans, exploits, or sends real
attack traffic. It is a bridge from HunterPy's triage output into Burp's
workflow.

## Build & install

You'll need:

1. **JDK 17+** on your `$PATH` (Burp's Montoya API targets 17)
2. The **Montoya API JAR** from your Burp install:
   - In Burp: **Extensions ▸ APIs ▸ Montoya API ▸ "View Javadoc"** —
     the JAR is linked from the same page
   - Or download from <https://github.com/PortSwigger/burp-extensions-montoya-api>
   - Drop it as `lib/montoya-api.jar`

Then:

```bash
cd gui/burp-extension
./build.sh
# Produces hunterpy-burp.jar
```

Install in Burp:
1. **Extensions ▸ Installed ▸ Add**
2. Extension type: **Java**
3. Select **`hunterpy-burp.jar`**
4. Open the new **HunterPy** tab and load any HunterPy `*.json` report

## What this is not

- A scanner. The extension never makes network requests.
- A live integration. You feed it JSON reports produced by
  `python main.py … --format json`.
- A replacement for the Burp XML exporter. If you want HunterPy issues
  in Burp **without installing this extension**, run
  `python main.py … --format burp` and use **Project options ▸ Misc ▸
  Issue import**.

## Architecture

```
src/main/java/io/hunterpy/burp/
├── HunterPyExtension.java   # BurpExtension entry point
├── HunterPyTab.java         # Swing UI + Site Map / Repeater / Issue actions
└── MiniJson.java            # ~200-line dependency-free JSON parser
```

We intentionally do not pull in Jackson or Gson — Burp's classpath
isolation makes shipping a fat-jar with conflicting transitive deps
unpleasant. Re-using HunterPy's tiny stdlib JSON parser keeps the JAR
small and conflict-free.

## Honest limitations

- The synthetic request HunterPy creates is a bare `GET /` against the
  finding's URL. Burp's Repeater will not replay any captured body or
  custom headers because HunterPy didn't capture them — the GUI is a
  triage layer, not a proxy.
- `siteMap.add(AuditIssue)` requires the Montoya API ≥ **2023.10**.
  Older Burp versions will need to use the **`--format burp` XML
  exporter** path instead.
- Compiled against the public Montoya API only. If PortSwigger renames
  a method, recompile against the new JAR.
