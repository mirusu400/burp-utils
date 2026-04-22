package io.theori.burpexim.collection;

import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class RepeaterCollection {
    private final List<HttpRequestResponse> items = new CopyOnWriteArrayList<>();
    private final List<ChangeListener> listeners = new CopyOnWriteArrayList<>();

    public void add(HttpRequestResponse rr) {
        items.add(rr);
        fire();
    }

    public void addAll(List<HttpRequestResponse> rrs) {
        items.addAll(rrs);
        fire();
    }

    public void clear() {
        items.clear();
        fire();
    }

    public List<HttpRequestResponse> snapshot() {
        return Collections.unmodifiableList(new ArrayList<>(items));
    }

    public int size() {
        return items.size();
    }

    public void addChangeListener(ChangeListener l) {
        listeners.add(l);
    }

    private void fire() {
        ChangeEvent evt = new ChangeEvent(this);
        for (ChangeListener l : listeners) {
            l.stateChanged(evt);
        }
    }
}
