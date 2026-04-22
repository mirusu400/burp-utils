package io.theori.burpexim.exporter;

import com.google.gson.GsonBuilder;
import io.theori.burpexim.model.RequestRecord;

import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class HarExporter {

    public static void write(List<RequestRecord> records, File file) throws IOException {
        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> logObj = new LinkedHashMap<>();
        logObj.put("version", "1.2");
        Map<String, Object> creator = new LinkedHashMap<>();
        creator.put("name", "burp-export-import");
        creator.put("version", "1.0");
        logObj.put("creator", creator);

        List<Map<String, Object>> entries = new ArrayList<>();
        for (RequestRecord r : records) {
            entries.add(toEntry(r));
        }
        logObj.put("entries", entries);
        root.put("log", logObj);

        try (Writer w = Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8)) {
            new GsonBuilder().setPrettyPrinting().disableHtmlEscaping()
                    .serializeNulls().create().toJson(root, w);
        }
    }

    private static Map<String, Object> toEntry(RequestRecord r) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("startedDateTime", r.startedDateTime);
        entry.put("time", 0);
        if (r.tabName != null) entry.put("_burpTabName", r.tabName);
        entry.put("request", toReq(r));
        entry.put("response", toResp(r));
        entry.put("cache", new LinkedHashMap<>());
        Map<String, Object> timings = new LinkedHashMap<>();
        timings.put("send", 0);
        timings.put("wait", 0);
        timings.put("receive", 0);
        entry.put("timings", timings);
        return entry;
    }

    private static Map<String, Object> toReq(RequestRecord r) {
        Map<String, Object> m = new LinkedHashMap<>();
        String raw = new String(r.requestBytes, StandardCharsets.ISO_8859_1);
        String[] parts = splitHeadersBody(raw);
        String headerBlock = parts[0];
        String body = parts[1];
        String[] lines = headerBlock.split("\r\n", -1);
        String startLine = lines.length > 0 ? lines[0] : "";
        String[] sl = startLine.split(" ", 3);

        m.put("method", r.method);
        m.put("url", r.url);
        m.put("httpVersion", sl.length >= 3 ? sl[2] : (r.httpVersion != null ? r.httpVersion : "HTTP/1.1"));
        m.put("cookies", new ArrayList<>());
        m.put("headers", parseHeaders(lines));
        m.put("queryString", parseQuery(r.url));
        if (!body.isEmpty()) {
            Map<String, Object> postData = new LinkedHashMap<>();
            postData.put("mimeType", headerValue(lines, "Content-Type"));
            postData.put("text", body);
            m.put("postData", postData);
        }
        m.put("headersSize", headerBlock.getBytes(StandardCharsets.ISO_8859_1).length);
        m.put("bodySize", body.getBytes(StandardCharsets.ISO_8859_1).length);
        m.put("_burpRaw", Base64.getEncoder().encodeToString(r.requestBytes));
        m.put("_burpHost", r.host);
        m.put("_burpPort", r.port);
        m.put("_burpSecure", r.secure);
        return m;
    }

    private static Map<String, Object> toResp(RequestRecord r) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (r.responseBytes == null || r.responseBytes.length == 0) {
            m.put("status", 0);
            m.put("statusText", "");
            m.put("httpVersion", "HTTP/1.1");
            m.put("cookies", new ArrayList<>());
            m.put("headers", new ArrayList<>());
            Map<String, Object> content = new LinkedHashMap<>();
            content.put("size", 0);
            content.put("mimeType", "");
            content.put("text", "");
            m.put("content", content);
            m.put("redirectURL", "");
            m.put("headersSize", -1);
            m.put("bodySize", -1);
            return m;
        }
        String raw = new String(r.responseBytes, StandardCharsets.ISO_8859_1);
        String[] parts = splitHeadersBody(raw);
        String headerBlock = parts[0];
        String body = parts[1];
        String[] lines = headerBlock.split("\r\n", -1);
        String startLine = lines.length > 0 ? lines[0] : "";
        String[] sl = startLine.split(" ", 3);

        int status = 0;
        String statusText = "";
        if (sl.length >= 2) {
            try { status = Integer.parseInt(sl[1]); } catch (Exception ignored) {}
        }
        if (sl.length >= 3) statusText = sl[2];

        m.put("status", status);
        m.put("statusText", statusText);
        m.put("httpVersion", sl.length >= 1 ? sl[0] : "HTTP/1.1");
        m.put("cookies", new ArrayList<>());
        m.put("headers", parseHeaders(lines));
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("size", body.getBytes(StandardCharsets.ISO_8859_1).length);
        content.put("mimeType", headerValue(lines, "Content-Type"));
        content.put("text", body);
        m.put("content", content);
        m.put("redirectURL", headerValue(lines, "Location"));
        m.put("headersSize", headerBlock.getBytes(StandardCharsets.ISO_8859_1).length);
        m.put("bodySize", body.getBytes(StandardCharsets.ISO_8859_1).length);
        m.put("_burpRaw", Base64.getEncoder().encodeToString(r.responseBytes));
        return m;
    }

    private static String[] splitHeadersBody(String raw) {
        int idx = raw.indexOf("\r\n\r\n");
        if (idx < 0) {
            int lf = raw.indexOf("\n\n");
            if (lf >= 0) return new String[]{raw.substring(0, lf), raw.substring(lf + 2)};
            return new String[]{raw, ""};
        }
        return new String[]{raw.substring(0, idx), raw.substring(idx + 4)};
    }

    private static List<Map<String, String>> parseHeaders(String[] lines) {
        List<Map<String, String>> out = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c < 0) continue;
            Map<String, String> h = new LinkedHashMap<>();
            h.put("name", lines[i].substring(0, c).trim());
            h.put("value", lines[i].substring(c + 1).trim());
            out.add(h);
        }
        return out;
    }

    private static String headerValue(String[] lines, String name) {
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c < 0) continue;
            if (lines[i].substring(0, c).trim().equalsIgnoreCase(name)) {
                return lines[i].substring(c + 1).trim();
            }
        }
        return "";
    }

    private static List<Map<String, String>> parseQuery(String url) {
        List<Map<String, String>> out = new ArrayList<>();
        if (url == null || url.isEmpty()) return out;
        try {
            URI u = URI.create(url);
            String q = u.getRawQuery();
            if (q == null) return out;
            for (String pair : q.split("&")) {
                if (pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                Map<String, String> kv = new LinkedHashMap<>();
                if (eq < 0) {
                    kv.put("name", pair);
                    kv.put("value", "");
                } else {
                    kv.put("name", pair.substring(0, eq));
                    kv.put("value", pair.substring(eq + 1));
                }
                out.add(kv);
            }
        } catch (Exception ignored) {}
        return out;
    }
}
