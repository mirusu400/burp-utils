package io.theori.burpexim.model;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.time.Instant;

public class RequestRecord {
    public String url;
    public String method;
    public String host;
    public int port;
    public boolean secure;
    public String httpVersion;
    public byte[] requestBytes;
    public byte[] responseBytes;
    public String startedDateTime;
    public String tabName;

    public static RequestRecord fromProxy(ProxyHttpRequestResponse p) {
        RequestRecord r = new RequestRecord();
        HttpRequest req = p.finalRequest();
        HttpService svc = req.httpService();
        r.url = safeUrl(req);
        r.method = req.method();
        r.host = svc != null ? svc.host() : "";
        r.port = svc != null ? svc.port() : 0;
        r.secure = svc != null && svc.secure();
        r.httpVersion = req.httpVersion();
        r.requestBytes = req.toByteArray().getBytes();
        HttpResponse resp = p.originalResponse();
        if (resp != null) {
            r.responseBytes = resp.toByteArray().getBytes();
        }
        try {
            r.startedDateTime = p.time().toInstant().toString();
        } catch (Exception e) {
            r.startedDateTime = Instant.now().toString();
        }
        return r;
    }

    public static RequestRecord fromRequestResponse(HttpRequestResponse rr) {
        RequestRecord r = new RequestRecord();
        HttpRequest req = rr.request();
        HttpService svc = req.httpService();
        r.url = safeUrl(req);
        r.method = req.method();
        r.host = svc != null ? svc.host() : "";
        r.port = svc != null ? svc.port() : 0;
        r.secure = svc != null && svc.secure();
        r.httpVersion = req.httpVersion();
        r.requestBytes = req.toByteArray().getBytes();
        HttpResponse resp = rr.response();
        if (resp != null) {
            r.responseBytes = resp.toByteArray().getBytes();
        }
        r.startedDateTime = Instant.now().toString();
        return r;
    }

    public HttpRequest toHttpRequest() {
        HttpService svc = HttpService.httpService(host, port, secure);
        return HttpRequest.httpRequest(svc, ByteArray.byteArray(requestBytes));
    }

    public HttpRequestResponse toRequestResponse() {
        HttpRequest req = toHttpRequest();
        if (responseBytes != null && responseBytes.length > 0) {
            HttpResponse resp = HttpResponse.httpResponse(ByteArray.byteArray(responseBytes));
            return HttpRequestResponse.httpRequestResponse(req, resp);
        }
        return HttpRequestResponse.httpRequestResponse(req,
                HttpResponse.httpResponse(ByteArray.byteArray(new byte[0])));
    }

    private static String safeUrl(HttpRequest req) {
        try {
            return req.url();
        } catch (Exception e) {
            return "";
        }
    }
}
