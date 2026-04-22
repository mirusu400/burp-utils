package io.theori.burpexim.importer;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import io.theori.burpexim.model.RequestRecord;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class HarImporter {

    public static List<RequestRecord> read(File file) throws IOException {
        List<RequestRecord> out = new ArrayList<>();
        try (Reader r = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
            JsonObject root = new Gson().fromJson(r, JsonObject.class);
            if (root == null || !root.has("log")) {
                throw new IOException("Invalid HAR: missing 'log' object");
            }
            JsonObject log = root.getAsJsonObject("log");
            if (!log.has("entries")) {
                throw new IOException("Invalid HAR: missing 'log.entries' array");
            }
            JsonArray entries = log.getAsJsonArray("entries");
            for (JsonElement e : entries) {
                JsonObject entry = e.getAsJsonObject();
                RequestRecord rec = parseEntry(entry);
                if (rec != null) out.add(rec);
            }
        }
        return out;
    }

    private static RequestRecord parseEntry(JsonObject entry) {
        RequestRecord rec = new RequestRecord();
        JsonObject req = entry.getAsJsonObject("request");
        if (req == null) return null;

        rec.url = getStr(req, "url", "");
        rec.method = getStr(req, "method", "GET");
        rec.httpVersion = getStr(req, "httpVersion", "HTTP/1.1");

        if (req.has("_burpRaw") && !req.get("_burpRaw").isJsonNull()) {
            rec.requestBytes = Base64.getDecoder().decode(req.get("_burpRaw").getAsString());
            rec.host = getStr(req, "_burpHost", "");
            rec.port = req.has("_burpPort") ? req.get("_burpPort").getAsInt() : 0;
            rec.secure = req.has("_burpSecure") && req.get("_burpSecure").getAsBoolean();
            if (rec.host.isEmpty() || rec.port == 0) {
                URI u = tryParse(rec.url);
                if (u != null) {
                    if (rec.host.isEmpty()) rec.host = u.getHost() != null ? u.getHost() : "";
                    rec.secure = "https".equalsIgnoreCase(u.getScheme());
                    if (rec.port == 0) rec.port = u.getPort() > 0 ? u.getPort() : (rec.secure ? 443 : 80);
                }
            }
        } else {
            rec.requestBytes = buildRawRequest(req, rec.url);
            URI u = tryParse(rec.url);
            if (u != null) {
                rec.host = u.getHost() != null ? u.getHost() : "";
                rec.secure = "https".equalsIgnoreCase(u.getScheme());
                rec.port = u.getPort() > 0 ? u.getPort() : (rec.secure ? 443 : 80);
            }
        }

        if (entry.has("response") && entry.get("response").isJsonObject()) {
            JsonObject resp = entry.getAsJsonObject("response");
            if (resp.has("_burpRaw") && !resp.get("_burpRaw").isJsonNull()) {
                rec.responseBytes = Base64.getDecoder().decode(resp.get("_burpRaw").getAsString());
            } else if (resp.has("status") && resp.get("status").getAsInt() > 0) {
                rec.responseBytes = buildRawResponse(resp);
            }
        }

        if (entry.has("_burpTabName") && !entry.get("_burpTabName").isJsonNull()) {
            rec.tabName = entry.get("_burpTabName").getAsString();
        }
        rec.startedDateTime = getStr(entry, "startedDateTime", "");
        return rec;
    }

    private static byte[] buildRawRequest(JsonObject req, String url) {
        StringBuilder sb = new StringBuilder();
        URI u = tryParse(url);
        String path;
        if (u != null) {
            path = (u.getRawPath() == null || u.getRawPath().isEmpty()) ? "/" : u.getRawPath();
            if (u.getRawQuery() != null) path += "?" + u.getRawQuery();
        } else {
            path = "/";
        }
        sb.append(getStr(req, "method", "GET")).append(' ').append(path).append(' ')
                .append(getStr(req, "httpVersion", "HTTP/1.1")).append("\r\n");
        boolean hasHost = false;
        if (req.has("headers") && req.get("headers").isJsonArray()) {
            for (JsonElement h : req.getAsJsonArray("headers")) {
                JsonObject ho = h.getAsJsonObject();
                String name = getStr(ho, "name", "");
                if (name.isEmpty()) continue;
                if (name.equalsIgnoreCase("Host")) hasHost = true;
                sb.append(name).append(": ").append(getStr(ho, "value", "")).append("\r\n");
            }
        }
        if (!hasHost && u != null && u.getHost() != null) {
            sb.append("Host: ").append(u.getHost()).append("\r\n");
        }
        sb.append("\r\n");
        String body = "";
        if (req.has("postData") && req.get("postData").isJsonObject()) {
            JsonObject pd = req.getAsJsonObject("postData");
            if (pd.has("text") && !pd.get("text").isJsonNull()) {
                body = pd.get("text").getAsString();
            }
        }
        return concat(sb.toString(), body);
    }

    private static byte[] buildRawResponse(JsonObject resp) {
        StringBuilder sb = new StringBuilder();
        sb.append(getStr(resp, "httpVersion", "HTTP/1.1")).append(' ')
                .append(resp.has("status") ? resp.get("status").getAsInt() : 0).append(' ')
                .append(getStr(resp, "statusText", "")).append("\r\n");
        if (resp.has("headers") && resp.get("headers").isJsonArray()) {
            for (JsonElement h : resp.getAsJsonArray("headers")) {
                JsonObject ho = h.getAsJsonObject();
                String name = getStr(ho, "name", "");
                if (name.isEmpty()) continue;
                sb.append(name).append(": ").append(getStr(ho, "value", "")).append("\r\n");
            }
        }
        sb.append("\r\n");
        String body = "";
        if (resp.has("content") && resp.get("content").isJsonObject()) {
            JsonObject c = resp.getAsJsonObject("content");
            if (c.has("text") && !c.get("text").isJsonNull()) {
                body = c.get("text").getAsString();
            }
        }
        return concat(sb.toString(), body);
    }

    private static byte[] concat(String headers, String body) {
        byte[] hb = headers.getBytes(StandardCharsets.ISO_8859_1);
        byte[] bb = body.getBytes(StandardCharsets.ISO_8859_1);
        byte[] out = new byte[hb.length + bb.length];
        System.arraycopy(hb, 0, out, 0, hb.length);
        System.arraycopy(bb, 0, out, hb.length, bb.length);
        return out;
    }

    private static URI tryParse(String s) {
        try { return URI.create(s); } catch (Exception e) { return null; }
    }

    private static String getStr(JsonObject o, String key, String fallback) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) return fallback;
        return o.get(key).getAsString();
    }
}
