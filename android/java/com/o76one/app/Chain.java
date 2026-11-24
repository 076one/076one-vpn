package com.o76one.app;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * v1.8.2 "کانفیگ + سایفون" (Config + Psiphon) mode, in the slot of the removed Worker mode.
 * The user's own proxy links (vless incl. Reality / ws / grpc / tcp / xhttp, vmess, trojan, shadowsocks), pasted,
 * imported from the clipboard or from a subscription URL, are stored only on the phone (files/chain/configs.json).
 * Runtime, one Go binary lib/<abi>/libchain.so (Xray-core v26.3.27, MPL-2.0 + psiphon-tunnel-core, GPL-3.0):
 *   Xray runs the chosen link as a SOCKS5 inbound on 127.0.0.1:<random port> (no auth, loopback only); with the
 *   "Psiphon layer" on, psiphon-tunnel-core runs with UpstreamProxyURL = socks5://127.0.0.1:<that port> and serves
 *   its own SOCKS5 on 127.0.0.1:<port>; o76core "svpn" carries the TUN into whichever SOCKS port is the outer one.
 * The app package is excluded from the VPN (addDisallowedApplication), so every core socket goes out directly.
 */
public final class Chain {
    private Chain() { }

    public static final String XRAY_VERSION = "v26.3.27";
    public static final String XRAY_REPO = "https://github.com/XTLS/Xray-core";
    public static final String PSIPHON_COMMIT = "6f412a9e0c31";
    public static final String[] REGIONS = {"", "DE", "NL", "GB", "FR", "US", "CA", "SE", "FI", "CH", "AT", "IT", "ES", "PL",
            "RO", "BE", "DK", "NO", "IE", "JP", "SG", "IN", "AU"};

    public static File bin(Context c) { return new File(c.getApplicationInfo().nativeLibraryDir, "libchain.so"); }
    public static boolean available(Context c) { File f = bin(c); return f.isFile() && f.length() > 1_000_000; }

    public static File dir(Context c) {
        File d = new File(c.getFilesDir(), "chain");
        if (!d.isDirectory()) //noinspection ResultOfMethodCallIgnored
            d.mkdirs();
        return d;
    }

    // ---------------- settings ----------------
    public static boolean psiphon(Context c) { return Core.prefs(c).getBoolean("chPsi", true); }
    public static void setPsiphon(Context c, boolean on) { Core.prefs(c).edit().putBoolean("chPsi", on).apply(); }
    public static String region(Context c) { return Core.prefs(c).getString("chRegion", ""); }
    public static void setRegion(Context c, String r) { Core.prefs(c).edit().putString("chRegion", r == null ? "" : r).apply(); }
    public static String subUrl(Context c) { return Core.prefs(c).getString("chSub", ""); }
    public static void setSubUrl(Context c, String u) { Core.prefs(c).edit().putString("chSub", u == null ? "" : u.trim()).apply(); }
    public static String regionLabel(String r) { return r == null || r.isEmpty() ? L.t("بهترین") : r; }
    /** v1.8.3: when every config fails with Psiphon on, try the best one without Psiphon (default off) */
    public static boolean noPsiFallback(Context c) { return Core.prefs(c).getBoolean("chNoPsiFb", false); }
    public static void setNoPsiFallback(Context c, boolean on) { Core.prefs(c).edit().putBoolean("chNoPsiFb", on).apply(); }

    // ---------------- v1.8.3 session overrides (automatic failover; never saved, reset on every connect) ----------------
    static volatile String overrideLink = "";
    static volatile Boolean overridePsi = null;

    public static void resetSession() { overrideLink = ""; overridePsi = null; }

    /** the config this session runs: the failover override when set (and still stored), else current() */
    public static JSONObject effective(Context c) {
        String o = overrideLink;
        if (!o.isEmpty()) for (JSONObject x : list(c)) if (x.optString("u").equals(o)) return x;
        return current(c);
    }

    public static boolean effectivePsi(Context c) { Boolean b = overridePsi; return b != null ? b : psiphon(c); }

    /** configs that passed their last test (ms > 0), fastest first */
    public static List<JSONObject> tested(Context c) {
        List<JSONObject> l = new ArrayList<>();
        for (JSONObject o : list(c)) if (o.optLong("ms", 0) > 0) l.add(o);
        java.util.Collections.sort(l, (a, b) -> Long.compare(a.optLong("ms"), b.optLong("ms")));
        return l;
    }

    // ---------------- stored configs ----------------
    private static final Object LOCK = new Object();
    private static File store(Context c) { return new File(dir(c), "configs.json"); }

    /** [{u: link, n: name, ms: latency (-1 failed, 0 untested), e: error, t: tested-at}] */
    public static List<JSONObject> list(Context c) {
        synchronized (LOCK) {
            List<JSONObject> out = new ArrayList<>();
            File f = store(c);
            if (!f.isFile()) return out;
            try (FileInputStream in = new FileInputStream(f)) {
                byte[] b = new byte[(int) f.length()];
                int off = 0, n;
                while (off < b.length && (n = in.read(b, off, b.length - off)) > 0) off += n;
                JSONArray a = new JSONArray(new String(b, 0, off, StandardCharsets.UTF_8));
                for (int i = 0; i < a.length(); i++) {
                    JSONObject o = a.optJSONObject(i);
                    if (o != null && !o.optString("u").isEmpty()) out.add(o);
                }
            } catch (Exception e) {
                Core.log("chain: configs.json: " + e.getMessage());
            }
            return out;
        }
    }

    static void save(Context c, List<JSONObject> l) {
        synchronized (LOCK) {
            JSONArray a = new JSONArray();
            for (JSONObject o : l) a.put(o);
            File tmp = new File(dir(c), "configs.json.tmp");
            try (FileOutputStream out = new FileOutputStream(tmp)) {
                out.write(a.toString().getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                Core.log("chain: save: " + e.getMessage());
                return;
            }
            //noinspection ResultOfMethodCallIgnored
            tmp.renameTo(store(c));
        }
    }

    public static String selected(Context c) { return Core.prefs(c).getString("chSel", ""); }
    public static void select(Context c, String link) { Core.prefs(c).edit().putString("chSel", link == null ? "" : link).apply(); }

    /** the chosen config: the selected one when still stored, else the fastest tested one, else the first */
    public static JSONObject current(Context c) {
        List<JSONObject> l = list(c);
        if (l.isEmpty()) return null;
        String s = selected(c);
        for (JSONObject o : l) if (o.optString("u").equals(s)) return o;
        JSONObject best = null;
        for (JSONObject o : l) {
            long ms = o.optLong("ms", 0);
            if (ms > 0 && (best == null || ms < best.optLong("ms"))) best = o;
        }
        return best != null ? best : l.get(0);
    }

    public static boolean configured(Context c) { return !list(c).isEmpty(); }

    public static void remove(Context c, String link) {
        List<JSONObject> l = list(c);
        for (int i = l.size() - 1; i >= 0; i--) if (l.get(i).optString("u").equals(link)) l.remove(i);
        save(c, l);
        if (link.equals(selected(c))) select(c, "");
    }

    public static void clear(Context c) { save(c, new ArrayList<JSONObject>()); select(c, ""); }

    static final String[] SCHEMES = {"vless://", "vmess://", "trojan://", "ss://"};

    public static boolean isLink(String s) {
        String l = s.trim().toLowerCase(Locale.US);
        for (String p : SCHEMES) if (l.startsWith(p)) return true;
        return false;
    }

    /** links found in pasted text: one per line / whitespace separated; a base64 subscription body is decoded too */
    public static List<String> extract(String text) {
        List<String> out = new ArrayList<>();
        if (text == null) return out;
        String t = text.trim();
        boolean any = false;
        for (String p : SCHEMES) if (t.toLowerCase(Locale.US).contains(p)) { any = true; break; }
        if (!any && t.length() > 16) {
            try {
                String d = new String(Base64.decode(t.replaceAll("\\s", ""), Base64.DEFAULT), StandardCharsets.UTF_8);
                for (String p : SCHEMES) if (d.toLowerCase(Locale.US).contains(p)) { t = d; break; }
            } catch (Exception ignored) { }
        }
        for (String w : t.split("[\\s]+")) {
            w = w.trim();
            if (isLink(w) && w.length() < 8192 && !out.contains(w)) out.add(w);
        }
        return out;
    }

    /** adds links (duplicates skipped); returns how many were new */
    public static int add(Context c, List<String> links) {
        List<JSONObject> l = list(c);
        int added = 0;
        outer:
        for (String u : links) {
            for (JSONObject o : l) if (o.optString("u").equals(u)) continue outer;
            try {
                JSONObject o = new JSONObject();
                o.put("u", u);
                o.put("n", name(u));
                o.put("ms", 0);
                l.add(o);
                added++;
            } catch (Exception ignored) { }
        }
        if (added > 0) save(c, l);
        return added;
    }

    /** display name: the #fragment (or vmess "ps"), else scheme + host */
    public static String name(String u) {
        try {
            String low = u.toLowerCase(Locale.US);
            if (low.startsWith("vmess://")) {
                String b = u.substring(8);
                int h = b.indexOf('#');
                if (h >= 0) b = b.substring(0, h);
                JSONObject o = new JSONObject(new String(Base64.decode(b.trim(), Base64.DEFAULT), StandardCharsets.UTF_8));
                String ps = o.optString("ps");
                return ps.isEmpty() ? "vmess " + o.optString("add") : ps;
            }
            int h = u.indexOf('#');
            if (h >= 0 && h + 1 < u.length()) return URLDecoder.decode(u.substring(h + 1).replace("+", "%2B"), "UTF-8");
            String scheme = u.substring(0, u.indexOf("://"));
            String rest = u.substring(u.indexOf("://") + 3);
            int at = rest.lastIndexOf('@');
            if (at >= 0) rest = rest.substring(at + 1);
            int q = rest.indexOf('?');
            if (q >= 0) rest = rest.substring(0, q);
            return scheme + " " + rest;
        } catch (Exception e) {
            return u.length() > 24 ? u.substring(0, 24) + "…" : u;
        }
    }

    public static String scheme(String u) {
        int i = u.indexOf("://");
        String s = i > 0 ? u.substring(0, i).toLowerCase(Locale.US) : "?";
        if ("vless".equals(s) && u.toLowerCase(Locale.US).contains("security=reality")) return "vless-reality";
        return s;
    }

    // ---------------- core process ----------------
    static Process start(Context c, List<String> args, boolean watchStdin) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(bin(c).getAbsolutePath());
        cmd.addAll(args);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir(c));
        pb.redirectErrorStream(true);
        Map<String, String> env = pb.environment();
        for (String k : new String[]{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"}) env.remove(k);
        env.put("HOME", dir(c).getAbsolutePath());
        if (watchStdin) env.put("CHAIN_WATCH_STDIN", "1");
        Process p = pb.start();
        if (!watchStdin) try { p.getOutputStream().close(); } catch (Exception ignored) { }
        return p;
    }

    /** fetches a subscription (base64 list or plain text) through the core; returns links or throws with the reason */
    public static List<String> fetchSub(Context c, String url) throws Exception {
        List<String> a = new ArrayList<>();
        a.add("sub"); a.add("-url"); a.add(url); a.add("-dns"); a.add(Core.systemDns(c));
        Process p = start(c, a, false);
        final List<String> links = new ArrayList<>();
        final StringBuilder err = new StringBuilder();
        Core.pump(p, line -> {
            if (line.startsWith("LINK ")) links.add(line.substring(5).trim());
            else if (line.startsWith("ERR ")) err.append(line.substring(4));
        });
        if (links.isEmpty() && err.length() > 0) throw new Exception(err.toString());
        return links;
    }

    public static volatile boolean testing;
    public static volatile String testStatus = "";

    /** real connectivity + latency test of every stored config (4 in parallel); results saved into the list */
    public static void testAll(Context c) {
        if (testing) return;
        testing = true;
        try {
            List<JSONObject> l = list(c);
            if (l.isEmpty()) { testStatus = ""; return; }
            testStatus = L.t("تست ") + l.size() + L.t(" کانفیگ …");
            File f = new File(dir(c), "test.txt");
            StringBuilder sb = new StringBuilder();
            for (JSONObject o : l) sb.append(o.optString("u")).append('\n');
            try (FileOutputStream out = new FileOutputStream(f)) { out.write(sb.toString().getBytes(StandardCharsets.UTF_8)); }
            List<String> a = new ArrayList<>();
            a.add("test"); a.add("-file"); a.add(f.getAbsolutePath()); a.add("-par"); a.add("4"); a.add("-timeout"); a.add("10");
            a.add("-dns"); a.add(Core.systemDns(c));
            Process p = start(c, a, false);
            final String[] ms = new String[l.size()], er = new String[l.size()];
            final int[] done = {0, 0};
            final int total = l.size();
            Core.pump(p, line -> {
                if (!line.startsWith("RES ")) return;
                String[] k = line.split(" ", 4);
                if (k.length < 3) return;
                try {
                    int i = Integer.parseInt(k[1]);
                    if (i < 0 || i >= total) return;
                    ms[i] = k[2];
                    er[i] = k.length > 3 ? k[3] : "";
                    done[0]++;
                    if (!"-1".equals(k[2])) done[1]++;
                    testStatus = L.t("تست کانفیگ‌ها: ") + done[0] + "/" + total + L.t(" — سالم: ") + done[1];
                } catch (Exception ignored) { }
            });
            //noinspection ResultOfMethodCallIgnored
            f.delete();
            // re-read: the list may have changed meanwhile; match by link
            List<JSONObject> cur = list(c);
            long now = System.currentTimeMillis();
            for (int i = 0; i < l.size(); i++) {
                if (ms[i] == null) continue;
                String u = l.get(i).optString("u");
                for (JSONObject o : cur) {
                    if (!o.optString("u").equals(u)) continue;
                    try {
                        long v = Long.parseLong(ms[i]);
                        o.put("ms", v < 0 ? -1 : Math.max(1, v));
                        o.put("e", v < 0 ? er[i] : "");
                        o.put("t", now);
                    } catch (Exception ignored) { }
                }
            }
            save(c, cur);
            testStatus = L.t("تست تمام شد: ") + done[1] + L.t(" از ") + total + L.t(" کانفیگ سالم");
            Core.log(L.t("کانفیگ + سایفون: ") + testStatus);
        } catch (Exception e) {
            testStatus = L.t("تست ناموفق: ") + e.getMessage();
            Core.log(testStatus);
        } finally {
            testing = false;
        }
    }

    public static String describe(Context c) {
        JSONObject o = effective(c);
        String n = o == null ? L.t("کانفیگی نیست") : o.optString("n");
        return n + (effectivePsi(c) ? L.t(" ← سایفون ") + regionLabel(region(c)) : L.t(" (بدون سایفون)"));
    }

    public static String diag(Context c) {
        JSONObject o = current(c);
        return "chain: available=" + available(c) + " configs=" + list(c).size() + " cur=" + (o == null ? "-" : scheme(o.optString("u")) + " ms=" + o.optLong("ms"))
                + " psiphon=" + psiphon(c) + " region=" + (region(c).isEmpty() ? "best" : region(c)) + "\n";
    }

    // ---------------- tunnel ----------------
    public static final int ST_CONFIG = 1, ST_PSIPHON = 2, ST_UP = 3;

    /** the tunnel being started / running (for the stage shown on the main screen) */
    public static volatile Run running;

    public static final class Run {
        Process p;
        int port;
        String name = "", link = "";
        boolean psi;
        /** v1.8.4 Bridge + Psiphon: the bridge key (scheme://ip:port, no credentials); "" in Config + Psiphon mode */
        String bridgeKey = "";

        boolean bridge() { return !bridgeKey.isEmpty(); }

        /** log prefix: "کانفیگ + سایفون: " or "پل + سایفون: " */
        String tag() { return bridge() ? L.t("پل + سایفون: ") : L.t("کانفیگ + سایفون: "); }
        volatile int stage;
        volatile boolean up, dead;
        volatile String err = "", exit = "", configErr = "", region = "";
        volatile long configMs;
        long startedAt = System.currentTimeMillis();
        /** v1.8.3 in-process recovery: 0 = none/pending, 1 = RECOVER_OK, 2 = RECOVER_FAIL */
        volatile int recoverResult;
        volatile String recoverMsg = "";
        volatile int tunnels = -1;
        /** v1.8.5: consecutive failed keep-alives through the chain ("KA n" from libchain; 0 = the last one passed) */
        volatile int kaFails;

        /** sends one control line to the core's stdin (RECOVER, XRAY_RESTART, PING) */
        synchronized boolean send(String cmd) {
            try {
                java.io.OutputStream os = p.getOutputStream();
                os.write((cmd + "\n").getBytes(StandardCharsets.UTF_8));
                os.flush();
                return true;
            } catch (Exception e) {
                Core.log("WLOG chain control " + cmd + ": " + e.getMessage());
                return false;
            }
        }

        void onLine(String l) {
            if (l.startsWith("RECOVER_OK")) { recoverMsg = l.substring(10).trim(); recoverResult = 1; Core.log("WLOG chain " + l); return; }
            if (l.startsWith("RECOVER_FAIL")) { recoverMsg = l.substring(12).trim(); recoverResult = 2; Core.log("WLOG chain " + l); return; }
            if (l.startsWith("PSI_TUNNELS ")) {
                try { tunnels = Integer.parseInt(l.substring(12).trim()); } catch (Exception ignored) { }
                Core.log("WLOG chain psiphon tunnels=" + tunnels);
                return;
            }
            if (l.startsWith("KA ")) {
                try { kaFails = Integer.parseInt(l.substring(3).trim()); } catch (Exception ignored) { }
                return;
            }
            if (l.startsWith("WLOG ")) { Core.log("WLOG chain: " + l.substring(5)); return; }
            if (l.startsWith("PONG")) return;
            if (l.startsWith("STAGE config")) { stage = ST_CONFIG; return; }
            if (l.startsWith("CONFIG_OK")) {
                try { configMs = Long.parseLong(l.substring(9).trim()); } catch (Exception ignored) { }
                Core.log(bridge() ? L.t("پل + سایفون: پروکسی پاسخ داد (") + configMs + "ms)" : L.t("کانفیگ + سایفون: کانفیگ وصل شد (") + configMs + "ms)");
                return;
            }
            if (l.startsWith("CONFIG_ERR")) {
                configErr = l.substring(10).trim();
                err = (bridge() ? L.t("پل کار نکرد: ") : L.t("کانفیگ کار نکرد: ")) + configErr;
                Core.log(tag() + err);
                return;
            }
            if (l.startsWith("BRIDGE ")) return; // detected scheme of an auto proxy
            if (l.startsWith("STAGE psiphon")) {
                stage = ST_PSIPHON;
                Core.log(bridge() ? L.t("پل + سایفون: اتصال سایفون از طریق پل…") : L.t("کانفیگ + سایفون: اتصال سایفون از داخل کانفیگ…"));
                return;
            }
            if (l.startsWith("PSI_UPSTREAM_ERR")) {
                err = (bridge() ? L.t("سایفون از طریق پل: ") : L.t("سایفون از داخل کانفیگ: ")) + l.substring(16).trim();
                return; // can repeat; summarised on failure
            }
            if (l.startsWith("PSI_ACTIVE ")) { region = l.substring(11).trim(); return; }
            if (l.startsWith("PSI_REGION ") || l.startsWith("PSI_CONNECTING")) return;
            if (l.startsWith("READY")) { stage = ST_UP; up = true; return; }
            if (l.startsWith("ERR ")) { err = l.substring(4).trim(); Core.log(tag() + err); return; }
            if (l.startsWith("WARN ")) { Core.log(tag() + l.substring(5)); return; }
            if (l.contains("[Warning] common/errors: The feature")) return; // Xray deprecation notices
            if (l.contains("[Error]")) { Core.log("xray: " + (l.length() > 240 ? l.substring(0, 240) : l)); }
        }

        public String stageLabel() {
            switch (stage) {
                case ST_CONFIG: return bridge() ? L.t("بررسی پل (پروکسی)…") : L.t("کانفیگ در حال اتصال…");
                case ST_PSIPHON: return L.t("سایفون در حال اتصال…");
                case ST_UP: return L.t("متصل");
                default: return "";
            }
        }
    }

    public static Run startTunnel(Context c, Core.Cancel cancelled) throws Exception {
        return startTunnel(c, cancelled, false);
    }

    /**
     * v1.8.4: bridge = true runs "Bridge + Psiphon": libchain run -upstream <bridge proxy> (Psiphon only, no Xray),
     * on the bridge Bridges.sessionBridge picks (the session's failover choice, else the pinned / best one).
     */
    public static Run startTunnel(Context c, Core.Cancel cancelled, boolean bridge) throws Exception {
        killStale(c);
        final Run r = new Run();
        File lf;
        List<String> a = new ArrayList<>();
        a.add("run");
        if (bridge) {
            JSONObject b = Bridges.sessionBridge(c);
            if (b == null) throw new Exception(L.t("هیچ پل سالمی برای سایفون نیست — در صفحهٔ «پل» با «سایفون» انتخاب‌شده «تست پل‌ها» را بزنید"));
            String url = b.optString("u", b.optString("k"));
            r.bridgeKey = b.optString("k");
            r.link = url;
            r.name = r.bridgeKey;
            r.psi = true;
            lf = new File(dir(c), "run.up");
            try (FileOutputStream out = new FileOutputStream(lf)) { out.write(url.getBytes(StandardCharsets.UTF_8)); }
            a.add("-upstream"); a.add("@" + lf.getAbsolutePath()); // credentials never appear in argv
            // v1.8.5: one proxy check only (a refusing bridge is skipped for the next healthy one, not retried);
            // keep-alive every 15 s so a stall shows up in time for the 40 s bridge switch
            a.add("-uptries"); a.add("1");
            a.add("-keepalive"); a.add("15s");
        } else {
            JSONObject cfg = effective(c);
            if (cfg == null) throw new Exception(L.t("هیچ کانفیگی ذخیره نشده — در صفحهٔ «کانفیگ + سایفون» لینک بچسبانید"));
            r.psi = effectivePsi(c);
            r.link = cfg.optString("u");
            r.name = cfg.optString("n");
            lf = new File(dir(c), "run.link");
            try (FileOutputStream out = new FileOutputStream(lf)) { out.write(cfg.optString("u").getBytes(StandardCharsets.UTF_8)); }
            a.add("-link"); a.add("@" + lf.getAbsolutePath()); // the link (with its secret) never appears in argv
            a.add("-psiphon=" + r.psi);
        }
        running = r;
        r.port = Aether.freePort();
        if (r.psi && !region(c).isEmpty()) { a.add("-region"); a.add(region(c)); }
        a.add("-socks"); a.add(String.valueOf(r.port));
        a.add("-dir"); a.add(dir(c).getAbsolutePath());
        a.add("-dns"); a.add(Core.systemDns(c));
        if (bridge) Core.log(L.t("پل + سایفون: شروع از طریق پل ") + r.bridgeKey + L.t(" ← سایفون ") + regionLabel(region(c)) + " socks=127.0.0.1:" + r.port);
        else Core.log(L.t("کانفیگ + سایفون: شروع «") + r.name + "» (" + scheme(r.link) + ")"
                + (r.psi ? L.t(" ← سایفون ") + regionLabel(region(c)) : L.t(" بدون لایهٔ سایفون")) + " socks=127.0.0.1:" + r.port);
        r.p = start(c, a, true);
        final Process p = r.p;
        new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) { line = line.trim(); if (!line.isEmpty()) r.onLine(line); }
            } catch (Exception ignored) { }
            int code = -1;
            try { code = p.waitFor(); } catch (InterruptedException ignored) { }
            r.dead = true;
            Core.log(r.tag() + L.t("پردازش پایان یافت (کد ") + code + ")");
        }, "o76-chain-log").start();
        long upMs = r.psi ? 240_000 : 60_000;
        try {
            while (!r.up) {
                if (cancelled.getAsBoolean()) { stop(r); throw new InterruptedException("cancelled"); }
                if (r.dead) {
                    if (r.bridge() && !r.configErr.isEmpty()) throw new BridgeRefused(r.bridgeKey, L.t("پل ") + r.bridgeKey + L.t(" کار نکرد: ") + r.configErr);
                    if (!r.configErr.isEmpty()) throw new Exception(L.t("کانفیگ «") + r.name + L.t("» کار نکرد: ") + r.configErr
                            + L.t(" — کانفیگ دیگری انتخاب کنید یا «تست همه» را بزنید"));
                    throw new Exception((r.bridge() ? L.t("پل + سایفون وصل نشد") : L.t("کانفیگ + سایفون وصل نشد")) + (r.err.isEmpty() ? "" : ": " + r.err));
                }
                if (System.currentTimeMillis() - r.startedAt > upMs) {
                    stop(r);
                    throw new Exception((r.stage == ST_PSIPHON ? (r.bridge() ? L.t("سایفون از طریق پل در ") : L.t("سایفون از داخل کانفیگ در "))
                            : (r.bridge() ? L.t("پل در ") : L.t("کانفیگ در ")))
                            + upMs / 1000 + L.t(" ثانیه وصل نشد") + (r.err.isEmpty() ? "" : " (" + r.err + ")"));
                }
                Thread.sleep(250);
            }
        } finally {
            //noinspection ResultOfMethodCallIgnored
            lf.delete(); // read by the core at start
        }
        r.exit = r.psi ? L.t("سایفون") + (r.region.isEmpty() || "<nil>".equals(r.region) ? "" : " " + r.region) + L.t(" از طریق ") + r.name : r.name;
        Core.log(r.tag() + L.t("آماده در ") + (System.currentTimeMillis() - r.startedAt) / 1000 + L.t(" ثانیه — ") + r.exit);
        return r;
    }

    /** v1.8.5: the bridge proxy failed its check at connect time (refused / no handshake): skip it for this session */
    public static final class BridgeRefused extends Exception {
        public final String key;
        BridgeRefused(String key, String msg) { super(msg); this.key = key; }
    }

    /**
     * v1.8.5 warm standby: proxy handshake + TLS abroad through each URL ("libchain ptest -real 0": stage 1 only,
     * no Psiphon). Blocking; returns the handshake ms per URL (-1 = failed), same order. Runs direct (the app is
     * excluded from its own VPN), like the bridge test.
     */
    public static long[] checkProxies(Context c, List<String> urls, int seconds) {
        final long[] ms = new long[urls.size()];
        java.util.Arrays.fill(ms, -1);
        if (urls.isEmpty() || !available(c)) return ms;
        File f = new File(dir(c), "warm.txt");
        try {
            StringBuilder sb = new StringBuilder();
            for (String u : urls) sb.append(u).append('\n');
            try (FileOutputStream out = new FileOutputStream(f)) { out.write(sb.toString().getBytes(StandardCharsets.UTF_8)); }
            List<String> a = new ArrayList<>();
            a.add("ptest"); a.add("-file"); a.add(f.getAbsolutePath()); a.add("-real"); a.add("0");
            a.add("-n"); a.add(String.valueOf(Math.max(1, urls.size()))); a.add("-hs"); a.add(String.valueOf(seconds));
            a.add("-dir"); a.add(dir(c).getAbsolutePath());
            a.add("-dns"); a.add(Core.systemDns(c));
            Process p = start(c, a, false);
            Core.pump(p, line -> {
                if (!line.startsWith("PHS ")) return;
                String[] k = line.split(" ");
                try {
                    int i = Integer.parseInt(k[1]);
                    if (i >= 0 && i < ms.length) ms[i] = Math.max(1, Long.parseLong(k[2]));
                } catch (Exception ignored) { }
            });
        } catch (Exception e) {
            Core.log("WLOG bridge standby check: " + e.getMessage());
        } finally {
            //noinspection ResultOfMethodCallIgnored
            f.delete();
        }
        return ms;
    }

    public static void stop(Run r) {
        if (r == null || r.p == null) return;
        try { r.p.getOutputStream().close(); } catch (Exception ignored) { } // stdin EOF -> the core exits by itself
        try { r.p.destroy(); } catch (Exception ignored) { }
        final Process p = r.p;
        new Thread(() -> {
            try {
                Thread.sleep(1500);
                p.exitValue();
            } catch (IllegalThreadStateException e) {
                try {
                    java.lang.reflect.Field f = p.getClass().getDeclaredField("pid");
                    f.setAccessible(true);
                    android.os.Process.killProcess(f.getInt(p));
                } catch (Exception ignored) { }
            } catch (Exception ignored) { }
        }, "o76-chain-kill").start();
    }

    /** kills libchain.so processes left from a previous app process */
    public static void killStale(Context c) {
        String me = bin(c).getAbsolutePath();
        File[] ps = new File("/proc").listFiles();
        if (ps == null) return;
        for (File d : ps) {
            String n = d.getName();
            if (n.isEmpty() || !Character.isDigit(n.charAt(0))) continue;
            try (FileInputStream in = new FileInputStream(new File(d, "cmdline"))) {
                byte[] b = new byte[512];
                int k = in.read(b);
                if (k <= 0) continue;
                String cl = new String(b, 0, k, StandardCharsets.UTF_8);
                // v1.8.4: never the children of a running bridge test (their data dirs are under chain/ptest/)
                if (cl.split("\0")[0].equals(me) && cl.contains("\0run\0") && !cl.contains("/ptest/")) android.os.Process.killProcess(Integer.parseInt(n));
            } catch (Exception ignored) { }
        }
    }
}
