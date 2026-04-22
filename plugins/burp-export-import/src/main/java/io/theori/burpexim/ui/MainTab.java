package io.theori.burpexim.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import io.theori.burpexim.collection.RepeaterCollection;
import io.theori.burpexim.exporter.HarExporter;
import io.theori.burpexim.exporter.JsonExporter;
import io.theori.burpexim.importer.HarImporter;
import io.theori.burpexim.importer.JsonImporter;
import io.theori.burpexim.model.RequestRecord;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.io.File;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class MainTab {
    private final MontoyaApi api;
    private final RepeaterCollection collection;
    private final JPanel root;
    private final JTextField historyDomainFilter = new JTextField(30);
    private final JTextField historyDateFrom = new JTextField(16);
    private final JTextField historyDateTo = new JTextField(16);
    private final JTextArea log = new JTextArea(14, 80);
    private final JLabel collectionSize = new JLabel("0 items");

    public MainTab(MontoyaApi api, RepeaterCollection collection) {
        this.api = api;
        this.collection = collection;
        this.root = build();
        collection.addChangeListener(e -> SwingUtilities.invokeLater(
                () -> collectionSize.setText(collection.size() + " items")));
    }

    public Component component() {
        return root;
    }

    private JPanel build() {
        JPanel main = new JPanel(new BorderLayout(8, 8));
        main.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));

        top.add(historyExportPanel());
        top.add(Box.createVerticalStrut(6));
        top.add(historyImportPanel());
        top.add(Box.createVerticalStrut(6));
        top.add(repeaterExportPanel());
        top.add(Box.createVerticalStrut(6));
        top.add(repeaterImportPanel());

        log.setEditable(false);
        log.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane logScroll = new JScrollPane(log);
        logScroll.setBorder(BorderFactory.createTitledBorder("Log"));

        main.add(top, BorderLayout.NORTH);
        main.add(logScroll, BorderLayout.CENTER);
        return main;
    }

    private JPanel historyExportPanel() {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createTitledBorder("History Export"));

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        row1.add(new JLabel("Domain filter (comma-separated, empty = all; supports *.example.com):"));
        row1.add(historyDomainFilter);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        row2.add(new JLabel("Date range (empty = no bound; YYYY-MM-DD or YYYY-MM-DD HH:mm[:ss], local time):"));
        row2.add(new JLabel("From"));
        row2.add(historyDateFrom);
        row2.add(new JLabel("To"));
        row2.add(historyDateTo);

        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        JButton har = new JButton("Export HAR");
        har.addActionListener(e -> doHistoryExport(true));
        JButton json = new JButton("Export JSON");
        json.addActionListener(e -> doHistoryExport(false));
        row3.add(har);
        row3.add(json);

        p.add(row1);
        p.add(row2);
        p.add(row3);
        return p;
    }

    private JPanel historyImportPanel() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        p.setBorder(BorderFactory.createTitledBorder("History Import (adds to Site Map)"));
        JButton har = new JButton("Import HAR");
        har.addActionListener(e -> doHistoryImport(true));
        JButton json = new JButton("Import JSON");
        json.addActionListener(e -> doHistoryImport(false));
        p.add(har);
        p.add(json);
        return p;
    }

    private JPanel repeaterExportPanel() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        p.setBorder(BorderFactory.createTitledBorder(
                "Repeater Export (via Collection — add items via context menu)"));
        p.add(new JLabel("Collection:"));
        p.add(collectionSize);
        JButton clear = new JButton("Clear Collection");
        clear.addActionListener(e -> {
            collection.clear();
            logLine("Cleared collection.");
        });
        JButton har = new JButton("Export HAR");
        har.addActionListener(e -> doRepeaterExport(true));
        JButton json = new JButton("Export JSON");
        json.addActionListener(e -> doRepeaterExport(false));
        p.add(clear);
        p.add(har);
        p.add(json);
        return p;
    }

    private JPanel repeaterImportPanel() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 6));
        p.setBorder(BorderFactory.createTitledBorder("Repeater Import (creates Repeater tabs)"));
        JButton har = new JButton("Import HAR");
        har.addActionListener(e -> doRepeaterImport(true));
        JButton json = new JButton("Import JSON");
        json.addActionListener(e -> doRepeaterImport(false));
        p.add(har);
        p.add(json);
        return p;
    }

    private void doHistoryExport(boolean har) {
        List<String> domains = parseDomains(historyDomainFilter.getText());
        ZonedDateTime from, to;
        try {
            from = parseDateTime(historyDateFrom.getText(), false);
            to = parseDateTime(historyDateTo.getText(), true);
        } catch (Exception ex) {
            logLine("Invalid date: " + ex.getMessage());
            return;
        }
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        List<RequestRecord> records = history.stream()
                .filter(h -> matchesDomain(hostOf(h), domains))
                .filter(h -> matchesDate(timeOf(h), from, to))
                .map(RequestRecord::fromProxy)
                .collect(Collectors.toList());

        if (records.isEmpty()) {
            logLine("No history entries matched filter.");
            return;
        }
        File file = chooseSave(har ? "history.har" : "history.json", har);
        if (file == null) return;
        try {
            if (har) HarExporter.write(records, file);
            else JsonExporter.write(records, file);
            logLine("Exported " + records.size() + " history entries -> " + file.getAbsolutePath());
        } catch (Exception ex) {
            logLine("History export failed: " + ex.getMessage());
        }
    }

    private void doHistoryImport(boolean har) {
        File file = chooseOpen(har);
        if (file == null) return;
        try {
            List<RequestRecord> records = har ? HarImporter.read(file) : JsonImporter.read(file);
            int ok = 0;
            for (RequestRecord r : records) {
                try {
                    HttpRequestResponse rr = r.toRequestResponse();
                    api.siteMap().add(rr);
                    ok++;
                } catch (Exception ex) {
                    logLine("  skip entry (" + r.url + "): " + ex.getMessage());
                }
            }
            logLine("Imported " + ok + "/" + records.size() + " entries into Site Map from "
                    + file.getName());
        } catch (Exception ex) {
            logLine("History import failed: " + ex.getMessage());
        }
    }

    private void doRepeaterExport(boolean har) {
        List<RequestRecord> records = collection.snapshot().stream()
                .map(RequestRecord::fromRequestResponse)
                .collect(Collectors.toList());
        if (records.isEmpty()) {
            logLine("Collection is empty. Right-click a request and pick "
                    + "'Add to Repeater Export Collection' first.");
            return;
        }
        File file = chooseSave(har ? "repeater.har" : "repeater.json", har);
        if (file == null) return;
        try {
            if (har) HarExporter.write(records, file);
            else JsonExporter.write(records, file);
            logLine("Exported " + records.size() + " repeater items -> " + file.getAbsolutePath());
        } catch (Exception ex) {
            logLine("Repeater export failed: " + ex.getMessage());
        }
    }

    private void doRepeaterImport(boolean har) {
        File file = chooseOpen(har);
        if (file == null) return;
        try {
            List<RequestRecord> records = har ? HarImporter.read(file) : JsonImporter.read(file);
            int ok = 0;
            int i = 1;
            for (RequestRecord r : records) {
                try {
                    String tabName = (r.tabName != null && !r.tabName.isEmpty())
                            ? r.tabName
                            : ("Imported #" + i);
                    api.repeater().sendToRepeater(r.toHttpRequest(), tabName);
                    ok++;
                } catch (Exception ex) {
                    logLine("  skip entry (" + r.url + "): " + ex.getMessage());
                }
                i++;
            }
            logLine("Sent " + ok + "/" + records.size() + " requests to Repeater from "
                    + file.getName());
        } catch (Exception ex) {
            logLine("Repeater import failed: " + ex.getMessage());
        }
    }

    private String hostOf(ProxyHttpRequestResponse h) {
        try {
            return h.finalRequest().httpService().host();
        } catch (Exception e) {
            return "";
        }
    }

    private ZonedDateTime timeOf(ProxyHttpRequestResponse h) {
        try {
            return h.time();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean matchesDate(ZonedDateTime t, ZonedDateTime from, ZonedDateTime to) {
        if (from == null && to == null) return true;
        if (t == null) return false;
        if (from != null && t.isBefore(from)) return false;
        if (to != null && t.isAfter(to)) return false;
        return true;
    }

    private static final DateTimeFormatter[] DATE_FORMATS = new DateTimeFormatter[]{
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm")
    };

    private ZonedDateTime parseDateTime(String raw, boolean endOfDay) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty()) return null;
        ZoneId zone = ZoneId.systemDefault();
        for (DateTimeFormatter f : DATE_FORMATS) {
            try {
                return LocalDateTime.parse(s, f).atZone(zone);
            } catch (Exception ignored) {}
        }
        try {
            LocalDate d = LocalDate.parse(s, DateTimeFormatter.ofPattern("yyyy-MM-dd"));
            LocalDateTime ldt = endOfDay ? d.atTime(23, 59, 59) : d.atStartOfDay();
            return ldt.atZone(zone);
        } catch (Exception e) {
            throw new IllegalArgumentException("cannot parse '" + s
                    + "' (expected yyyy-MM-dd or yyyy-MM-dd HH:mm[:ss])");
        }
    }

    private File chooseSave(String defaultName, boolean har) {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File(defaultName));
        fc.setFileFilter(new FileNameExtensionFilter(har ? "HAR" : "JSON", har ? "har" : "json"));
        int res = fc.showSaveDialog(root);
        return res == JFileChooser.APPROVE_OPTION ? fc.getSelectedFile() : null;
    }

    private File chooseOpen(boolean har) {
        JFileChooser fc = new JFileChooser();
        fc.setFileFilter(new FileNameExtensionFilter(har ? "HAR" : "JSON", har ? "har" : "json"));
        int res = fc.showOpenDialog(root);
        return res == JFileChooser.APPROVE_OPTION ? fc.getSelectedFile() : null;
    }

    private List<String> parseDomains(String raw) {
        if (raw == null || raw.isBlank()) return new ArrayList<>();
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    private boolean matchesDomain(String host, List<String> filters) {
        if (filters.isEmpty()) return true;
        if (host == null) host = "";
        String h = host.toLowerCase();
        for (String f : filters) {
            String fl = f.toLowerCase();
            if (fl.startsWith("*.")) {
                String bare = fl.substring(2);
                if (h.equals(bare) || h.endsWith("." + bare)) return true;
            } else if (h.equals(fl) || h.endsWith("." + fl)) {
                return true;
            }
        }
        return false;
    }

    private void logLine(String s) {
        SwingUtilities.invokeLater(() -> log.append(s + "\n"));
        api.logging().logToOutput(s);
    }
}
