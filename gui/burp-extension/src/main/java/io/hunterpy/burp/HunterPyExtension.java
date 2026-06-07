package io.hunterpy.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

/**
 * Entry point registered with Burp via META-INF/services/burp.api.montoya.BurpExtension.
 *
 * <p>Built against the Montoya API (Burp Suite 2023.10+). Compile by
 * dropping {@code montoya-api-2024.x.jar} from your Burp install into
 * {@code lib/} and running {@code ./build.sh}.</p>
 */
public final class HunterPyExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("HunterPy — Findings Bridge");
        Logging log = api.logging();
        log.logToOutput("[HunterPy] Extension initialised.");

        // The tab is the only UI surface — everything else (Site Map +
        // Repeater enrichment) is triggered from buttons on that tab.
        HunterPyTab tab = new HunterPyTab(api);
        api.userInterface().registerSuiteTab("HunterPy", tab.getRootComponent());

        log.logToOutput("[HunterPy] Tab registered. Load a HunterPy JSON "
            + "report from the tab to begin.");
    }
}
