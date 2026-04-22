package io.theori.burpexim;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import io.theori.burpexim.collection.RepeaterCollection;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class CollectContextMenu implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final RepeaterCollection collection;

    public CollectContextMenu(MontoyaApi api, RepeaterCollection collection) {
        this.api = api;
        this.collection = collection;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();
        JMenuItem add = new JMenuItem("Add to Repeater Export Collection");
        add.addActionListener(e -> {
            List<HttpRequestResponse> targets = new ArrayList<>(event.selectedRequestResponses());
            if (targets.isEmpty()) {
                Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
                editor.ifPresent(m -> targets.add(m.requestResponse()));
            }
            if (targets.isEmpty()) {
                api.logging().logToOutput("Nothing selected to add.");
                return;
            }
            collection.addAll(targets);
            api.logging().logToOutput("Added " + targets.size()
                    + " items to Repeater Export Collection (total: " + collection.size() + ")");
        });
        items.add(add);
        return items;
    }
}
