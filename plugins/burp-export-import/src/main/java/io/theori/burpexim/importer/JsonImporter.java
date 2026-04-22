package io.theori.burpexim.importer;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import io.theori.burpexim.model.RequestRecord;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class JsonImporter {

    public static List<RequestRecord> read(File file) throws IOException {
        List<RequestRecord> out = new ArrayList<>();
        try (Reader r = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
            JsonObject root = new Gson().fromJson(r, JsonObject.class);
            if (root == null || !root.has("entries")) {
                throw new IOException("Invalid JSON: missing 'entries' array");
            }
            JsonArray arr = root.getAsJsonArray("entries");
            for (JsonElement e : arr) {
                JsonObject o = e.getAsJsonObject();
                RequestRecord rec = new RequestRecord();
                rec.url = getStr(o, "url", "");
                rec.method = getStr(o, "method", "GET");
                rec.host = getStr(o, "host", "");
                rec.port = o.has("port") ? o.get("port").getAsInt() : 0;
                rec.secure = o.has("secure") && o.get("secure").getAsBoolean();
                rec.httpVersion = getStr(o, "httpVersion", "HTTP/1.1");
                rec.startedDateTime = getStr(o, "startedDateTime", "");
                if (o.has("tabName") && !o.get("tabName").isJsonNull()) {
                    rec.tabName = o.get("tabName").getAsString();
                }
                if (o.has("request") && !o.get("request").isJsonNull()) {
                    rec.requestBytes = Base64.getDecoder().decode(o.get("request").getAsString());
                }
                if (o.has("response") && !o.get("response").isJsonNull()) {
                    rec.responseBytes = Base64.getDecoder().decode(o.get("response").getAsString());
                }
                if (rec.requestBytes != null) out.add(rec);
            }
        }
        return out;
    }

    private static String getStr(JsonObject o, String key, String fallback) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) return fallback;
        return o.get(key).getAsString();
    }
}
