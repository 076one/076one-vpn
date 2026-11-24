package com.o76one.app;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * v1.8.5 in-app updater, platform-independent part (plain Java + org.json, so it can be tested on a desktop JVM):
 * parses release/latest.json, picks the APK for the phone's ABIs, downloads over HTTP/1.1 either directly or through
 * the app's own local SOCKS5 port (the tunnel), follows redirects (github.com/…/raw/… -> raw.githubusercontent.com),
 * and checks SHA-256 and the APK's v1 (JAR) signer certificate.
 */
public final class UpdCore {
    private UpdCore() { }

    public static final String REPO = "https://github.com/076one/076one-vpn";
    /** raw file URL base on the public repo (branch main); redirects to raw.githubusercontent.com */
    public static final String RAW = REPO + "/raw/main/";
    public static final String MANIFEST_URL = RAW + "release/latest.json";

    /** set by the Android side (HttpsURLConnection's default verifier); https needs it */
    public static volatile HostnameVerifier verifier;
    public static volatile String userAgent = "076one-updater";

    public interface Progress { void on(long done, long total); }
    public interface Cancel { boolean cancelled(); }

    // ---------------- manifest ----------------
    public static final class Info {
        public int versionCode, minSdk;
        public String versionName = "", abi = "", url = "", sha256 = "", notes = "", file = "";
        public long size;
    }

    /** "release/x.apk" -> RAW + path; absolute http(s) URLs stay as they are */
    public static String rawUrl(String pathOrUrl) {
        String s = pathOrUrl == null ? "" : pathOrUrl.trim();
        if (s.startsWith("https://") || s.startsWith("http://")) return s;
        while (s.startsWith("/")) s = s.substring(1);
        return RAW + s;
    }

    /**
     * Parses latest.json and picks the APK: arm64-v8a when the phone lists it, else armeabi-v7a, else the
     * universal one. lang = fa | en | zh for the notes.
     */
    public static Info parse(String json, String[] abis, String lang) throws Exception {
        JSONObject o = new JSONObject(json);
        Info in = new Info();
        in.versionCode = o.getInt("versionCode");
        in.versionName = o.optString("versionName", String.valueOf(in.versionCode));
        in.minSdk = o.optInt("minSdk", 21);
        JSONObject notes = o.optJSONObject("notes");
        if (notes != null) {
            in.notes = notes.optString(lang, "");
            if (in.notes.isEmpty()) in.notes = notes.optString("fa", notes.optString("en", ""));
        }
        Map<String, JSONObject> byAbi = new HashMap<>();
        JSONArray apks = o.optJSONArray("apks");
        if (apks != null) for (int i = 0; i < apks.length(); i++) {
            JSONObject a = apks.optJSONObject(i);
            if (a != null && !a.optString("abi").isEmpty()) byAbi.put(a.optString("abi"), a);
        }
        Set<String> have = new HashSet<>();
        if (abis != null) for (String a : abis) if (a != null) have.add(a.trim());
        JSONObject pick = null;
        if (have.contains("arm64-v8a")) pick = byAbi.get("arm64-v8a");
        if (pick == null && (have.contains("armeabi-v7a") || have.contains("armeabi") || have.contains("arm64-v8a")))
            pick = byAbi.get("armeabi-v7a");
        if (pick == null) pick = byAbi.get("universal");
        if (pick == null && o.has("sha256")) pick = o; // flat manifest: top level describes the universal APK
        if (pick == null) throw new Exception("latest.json: no APK for this phone");
        in.abi = pick.optString("abi", "universal");
        in.file = pick.optString("apk", pick.optString("file", ""));
        String u = pick.optString("url", "");
        in.url = u.isEmpty() ? rawUrl(in.file) : u;
        if (in.url.isEmpty() || in.url.equals(RAW)) throw new Exception("latest.json: no APK url");
        in.sha256 = pick.optString("sha256", "").trim().toLowerCase(Locale.US);
        if (!in.sha256.matches("[0-9a-f]{64}")) throw new Exception("latest.json: bad sha256");
        in.size = pick.optLong("size", 0);
        return in;
    }

    // ---------------- HTTP/1.1 over a direct or SOCKS5 socket ----------------
    static final class Resp {
        int code;
        final Map<String, String> h = new HashMap<>();
        InputStream body;
        Socket sock;
        long length = -1;

        void close() { try { sock.close(); } catch (Exception ignored) { } }
    }

    static Socket connect(String host, int port, int socksPort, int timeoutMs) throws IOException {
        Socket s = new Socket();
        try {
            if (socksPort <= 0) {
                s.connect(new InetSocketAddress(host, port), timeoutMs);
                s.setSoTimeout(timeoutMs);
                return s;
            }
            s.connect(new InetSocketAddress("127.0.0.1", socksPort), timeoutMs);
            s.setSoTimeout(timeoutMs);
            OutputStream o = s.getOutputStream();
            InputStream i = s.getInputStream();
            o.write(new byte[]{5, 1, 0});
            o.flush();
            byte[] g = readN(i, 2);
            if (g[0] != 5 || g[1] != 0) throw new IOException("local SOCKS refused the greeting");
            byte[] hb = host.getBytes(StandardCharsets.US_ASCII);
            if (hb.length > 255) throw new IOException("host name too long");
            ByteArrayOutputStream req = new ByteArrayOutputStream();
            req.write(new byte[]{5, 1, 0, 3, (byte) hb.length});
            req.write(hb);
            req.write((port >> 8) & 0xff);
            req.write(port & 0xff);
            o.write(req.toByteArray());
            o.flush();
            byte[] r = readN(i, 4);
            if (r[1] != 0) throw new IOException("tunnel could not reach " + host + " (SOCKS reply " + r[1] + ")");
            int skip = r[3] == 1 ? 6 : r[3] == 4 ? 18 : (readN(i, 1)[0] & 0xff) + 2;
            readN(i, skip);
            return s;
        } catch (IOException e) {
            try { s.close(); } catch (Exception ignored) { }
            throw e;
        }
    }

    static byte[] readN(InputStream in, int n) throws IOException {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n) {
            int k = in.read(b, off, n - off);
            if (k < 0) throw new IOException("connection closed");
            off += k;
        }
        return b;
    }

    static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') break;
            if (c != '\r') b.write(c);
            if (b.size() > 16384) throw new IOException("header line too long");
        }
        if (c < 0 && b.size() == 0) throw new IOException("connection closed");
        return new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    /** GET with up to 6 redirects; returns the 200 response (caller closes) or throws with the status */
    static Resp get(String url, int socksPort, int timeoutMs) throws IOException {
        URL u = new URL(url);
        for (int hop = 0; hop < 7; hop++) {
            String proto = u.getProtocol();
            boolean tls = "https".equals(proto);
            if (!tls && !"http".equals(proto)) throw new IOException("unsupported URL " + u);
            String host = u.getHost();
            int port = u.getPort() > 0 ? u.getPort() : (tls ? 443 : 80);
            Socket s = connect(host, port, socksPort, timeoutMs);
            Resp r = new Resp();
            r.sock = s;
            try {
                if (tls) {
                    HostnameVerifier v = verifier;
                    if (v == null) throw new IOException("no hostname verifier");
                    SSLSocket ss = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(s, host, port, true);
                    ss.setSoTimeout(timeoutMs);
                    ss.startHandshake();
                    if (!v.verify(host, ss.getSession())) throw new IOException("TLS certificate does not match " + host);
                    r.sock = ss;
                }
                String path = u.getFile();
                if (path == null || path.isEmpty()) path = "/";
                String req = "GET " + path + " HTTP/1.1\r\nHost: " + host + (u.getPort() > 0 ? ":" + u.getPort() : "")
                        + "\r\nUser-Agent: " + userAgent + "\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n";
                OutputStream o = r.sock.getOutputStream();
                o.write(req.getBytes(StandardCharsets.ISO_8859_1));
                o.flush();
                InputStream in = new BufferedInputStream(r.sock.getInputStream(), 65536);
                String st = readLine(in);
                String[] sp = st.split(" ", 3);
                if (sp.length < 2 || !sp[0].startsWith("HTTP/")) throw new IOException("bad HTTP answer from " + host);
                r.code = Integer.parseInt(sp[1].trim());
                String line;
                while (!(line = readLine(in)).isEmpty()) {
                    int c = line.indexOf(':');
                    if (c > 0) r.h.put(line.substring(0, c).trim().toLowerCase(Locale.US), line.substring(c + 1).trim());
                }
                if (r.code >= 300 && r.code < 400 && r.h.containsKey("location")) {
                    r.close();
                    u = new URL(u, r.h.get("location"));
                    continue;
                }
                if (r.code != 200) throw new IOException("HTTP " + r.code + " from " + host);
                if ("chunked".equalsIgnoreCase(r.h.get("transfer-encoding"))) r.body = new Chunked(in);
                else {
                    String cl = r.h.get("content-length");
                    if (cl != null) {
                        r.length = Long.parseLong(cl.trim());
                        r.body = new Limited(in, r.length);
                    } else r.body = in;
                }
                return r;
            } catch (IOException | RuntimeException e) {
                r.close();
                throw e instanceof IOException ? (IOException) e : new IOException(e.toString());
            }
        }
        throw new IOException("too many redirects");
    }

    /** small text body (the manifest), at most max bytes */
    public static String getText(String url, int socksPort, int max) throws IOException {
        Resp r = get(url, socksPort, 20000);
        try {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = r.body.read(buf)) > 0) {
                b.write(buf, 0, n);
                if (b.size() > max) throw new IOException("answer too large");
            }
            return new String(b.toByteArray(), StandardCharsets.UTF_8);
        } finally {
            r.close();
        }
    }

    /** downloads to out; returns the bytes written. expected > 0: the size latest.json gives (checked) */
    public static long download(String url, int socksPort, OutputStream out, long expected, Progress p, Cancel c) throws IOException {
        Resp r = get(url, socksPort, 30000);
        try {
            long total = r.length > 0 ? r.length : expected;
            if (expected > 0 && r.length > 0 && r.length != expected)
                throw new IOException("size " + r.length + " differs from latest.json (" + expected + ")");
            byte[] buf = new byte[65536];
            long done = 0, lastP = 0;
            int n;
            while ((n = r.body.read(buf)) > 0) {
                if (c != null && c.cancelled()) throw new IOException("cancelled");
                out.write(buf, 0, n);
                done += n;
                if (expected > 0 && done > expected) throw new IOException("larger than latest.json says");
                if (p != null && done - lastP >= 128 * 1024) { lastP = done; p.on(done, total); }
            }
            if (p != null) p.on(done, total);
            if (r.length > 0 && done != r.length) throw new IOException("download cut off at " + done + " of " + r.length + " bytes");
            return done;
        } finally {
            r.close();
        }
    }

    static final class Limited extends FilterInputStream {
        long left;
        Limited(InputStream in, long n) { super(in); left = n; }
        @Override public int read() throws IOException { if (left <= 0) return -1; int c = super.read(); if (c >= 0) left--; return c; }
        @Override public int read(byte[] b, int off, int len) throws IOException {
            if (left <= 0) return -1;
            int n = super.read(b, off, (int) Math.min(len, left));
            if (n > 0) left -= n;
            return n;
        }
    }

    static final class Chunked extends InputStream {
        final InputStream in;
        long left;
        boolean eof;
        Chunked(InputStream in) { this.in = in; }
        private boolean next() throws IOException {
            if (eof) return false;
            if (left > 0) return true;
            String l = readLine(in);
            if (l.isEmpty()) l = readLine(in); // CRLF after the previous chunk
            int sc = l.indexOf(';');
            left = Long.parseLong((sc >= 0 ? l.substring(0, sc) : l).trim(), 16);
            if (left == 0) {
                eof = true;
                String t;
                while (!(t = readLine(in)).isEmpty()) { /* trailers */ }
                return false;
            }
            return true;
        }
        @Override public int read() throws IOException {
            byte[] b = new byte[1];
            return read(b, 0, 1) < 0 ? -1 : b[0] & 0xff;
        }
        @Override public int read(byte[] b, int off, int len) throws IOException {
            if (!next()) return -1;
            int n = in.read(b, off, (int) Math.min(len, left));
            if (n < 0) throw new IOException("chunked body cut off");
            left -= n;
            return n;
        }
    }

    // ---------------- checks ----------------
    public static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format(Locale.US, "%02x", x & 0xff));
        return sb.toString();
    }

    public static String sha256(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = new FileInputStream(f)) {
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) > 0) md.update(b, 0, n);
        }
        return hex(md.digest());
    }

    public static String sha256(byte[] b) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(b));
    }

    /**
     * Verifies the APK's v1 (JAR) signature over every entry (a changed entry throws SecurityException) and returns
     * the SHA-256 of the certificates that signed ALL entries. Empty set = not (fully) signed.
     */
    public static Set<String> v1SignerCerts(File apk) throws Exception {
        Set<String> common = null;
        byte[] buf = new byte[65536];
        try (JarFile jf = new JarFile(apk, true)) {
            Enumeration<JarEntry> en = jf.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                String n = e.getName();
                if (n.startsWith("META-INF/")) continue; // signature files themselves
                try (InputStream in = jf.getInputStream(e)) {
                    while (in.read(buf) > 0) { /* reading verifies the digest */ }
                }
                Certificate[] cs = e.getCertificates();
                if (cs == null || cs.length == 0) throw new SecurityException("unsigned entry " + n);
                Set<String> s = new HashSet<>();
                for (Certificate c : cs) s.add(sha256(c.getEncoded()));
                if (common == null) common = s;
                else common.retainAll(s);
                if (common.isEmpty()) return common;
            }
        }
        return common == null ? new HashSet<String>() : common;
    }

    /** full check of a downloaded APK: SHA-256 as latest.json says, signed by one of `own` (the app's own certs) */
    public static void verify(File apk, Info in, Set<String> own) throws Exception {
        String sha = sha256(apk);
        if (!sha.equalsIgnoreCase(in.sha256)) throw new SecurityException("SHA-256 mismatch: " + sha.substring(0, 16) + "… ≠ " + in.sha256.substring(0, 16) + "…");
        Set<String> signers = v1SignerCerts(apk);
        if (signers.isEmpty()) throw new SecurityException("APK signature missing or invalid");
        Set<String> x = new HashSet<>(signers);
        x.retainAll(own);
        if (x.isEmpty()) throw new SecurityException("APK signed by another key (" + signers.iterator().next().substring(0, 16) + "…)");
    }
}
