package io.theori.burpexim;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import io.theori.burpexim.collection.RepeaterCollection;
import io.theori.burpexim.ui.MainTab;

public class BurpExportImport implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Export/Import (History & Repeater)");
        RepeaterCollection collection = new RepeaterCollection();
        MainTab tab = new MainTab(api, collection);
        api.userInterface().registerSuiteTab("Export/Import", tab.component());
        api.userInterface().registerContextMenuItemsProvider(
                new CollectContextMenu(api, collection));
        api.logging().logToOutput("Export/Import extension loaded.");
    }
}
