package io.theori.burpexim.exporter;

import com.google.gson.GsonBuilder;
import io.theori.burpexim.model.RequestRecord;

import java.io.File;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class JsonExporter {
    public static void write(List<RequestRecord> records, File file) throws IOException {
        List<Map<String, Object>> arr = new ArrayList<>();
        for (RequestRecord r : records) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("url", r.url);
            m.put("method", r.method);
            m.put("host", r.host);
            m.put("port", r.port);
            m.put("secure", r.secure);
            m.put("httpVersion", r.httpVersion);
            m.put("startedDateTime", r.startedDateTime);
            m.put("tabName", r.tabName);
            m.put("request", Base64.getEncoder().encodeToString(r.requestBytes));
            if (r.responseBytes != null) {
                m.put("response", Base64.getEncoder().encodeToString(r.responseBytes));
            }
            arr.add(m);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("format", "burp-export-import/v1");
        out.put("entries", arr);
        try (Writer w = Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8)) {
            new GsonBuilder().setPrettyPrinting().disableHtmlEscaping()
                    .serializeNulls().create().toJson(out, w);
        }
    }
}
