package com.o76one.app;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * v1.3 "bridge": phone -> public SOCKS5 / SOCKS4 / HTTP-CONNECT proxy -> Cloudflare MASQUE over HTTP/2.
 * The MASQUE TLS (client cert + pinned server key) runs end-to-end inside the proxied TCP stream.
 *
 * Storage:
 *   files/bridges_user.txt   proxies the user pasted (normalised URLs, may contain user:pass) - tested first
 *   files/bridges_pool.txt   proxies downloaded from public lists (no credentials)
 *   prefs "bridgeRes"        tested results: [{k:"scheme://ip:port", u:url, ok:1|0|-1, hs, rms, kbps, ep, sni, colo, t, ft,
 *                            intl:1|0 (v1.5 BINTL: proxy reached a server abroad / domestic-only), kind:"m" ("w" = tested by the removed Worker mode)}]
 *   prefs "bridgeIR"         v1.5: only proxies located in Iran (fetchlists -country IR + ipfilter -country IR)
 */
public final class Bridges {
    /** type|url|mirror  (all verified to return a plain ip:port list on 2026-11-21) */
    public static final String[] DEFAULT_SOURCES = {
            "socks5|https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt|https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks5.txt",
            "http|https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt|https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/http.txt",
            "socks4|https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt|https://cdn.jsdelivr.net/gh/monosans/proxy-list@main/proxies/socks4.txt",
            "socks5|https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt|https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
            "http|https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt|https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
            "socks5|https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt|https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
            "http|https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt|https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/http.txt",
            "socks5|https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt|https://cdn.jsdelivr.net/gh/hookzof/socks5_list@master/proxy.txt",
            "auto|https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&proxy_format=protocolipport&format=text",
            "auto|https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=protocolipport&format=text",
    };
    /**
     * v1.5 sources that are already Iran-only ("type@IR" = trusted by fetchlists -country IR without a range check).
     * All three returned Iranian proxies on 2026-11-22 (geonode JSON, proxyscrape text, proxifly text).
     */
    public static final String[] IR_SOURCES = {
            "auto@IR|https://proxylist.geonode.com/api/proxy-list?country=IR&limit=500&page=1&sort_by=lastChecked&sort_type=desc",
            "auto@IR|https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&country=ir&protocol=all&proxy_format=protocolipport&format=text",
            "auto@IR|https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/countries/IR/data.txt|https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/countries/IR/data.txt",
    };
    public static final int MAX_TEST = 1000, CONC = 50;
    /** v1.8.4 Psiphon test: proxies handshaked per run, real Psiphon connects (3 at a time, 75 s each) */
    public static final int PSI_MAX = 300, PSI_CONC = 60, PSI_REAL = 6, PSI_PAR = 3, PSI_KEEP = 3, PSI_TIMEOUT = 75;
    /** a bridge that failed is not auto-picked again for this long */
    public static final long FAIL_COOLDOWN_MS = 10L * 60 * 1000;
    public static final long FRESH_MS = 3L * 3600 * 1000;

    public static volatile boolean busy;
    public static volatile String status = "";
    private static volatile Process proc;
    private static volatile boolean stopReq;
    private static final Object LOCK = new Object();
    private static volatile int version;

    public static int version() { return version; }

    // ------------------------------------------------------------ settings
    /** v1.4: the bridge is one of the three connection modes */
    public static boolean enabled(Context c) { return Core.MODE_BRIDGE.equals(Core.mode(c)); }

    public static void setEnabled(Context c, boolean on) {
        Core.setMode(c, on ? Core.MODE_BRIDGE : Core.MODE_WARP);
        version++;
    }

    // ------------------------------------------------------------ v1.8.4 what runs through the bridge
    /** WARP (MASQUE, the original bridge) or Psiphon (libchain with the bridge as Psiphon's upstream proxy) */
    public static final String VIA_WARP = "warp", VIA_PSI = "psiphon";

    public static String via(Context c) { return VIA_PSI.equals(Core.prefs(c).getString("bridgeVia", VIA_WARP)) ? VIA_PSI : VIA_WARP; }

    public static boolean viaPsiphon(Context c) { return VIA_PSI.equals(via(c)); }

    public static void setVia(Context c, String v) {
        if (v.equals(via(c))) return;
        Core.prefs(c).edit().putString("bridgeVia", VIA_PSI.equals(v) ? VIA_PSI : VIA_WARP).apply();
        Core.log(L.t("پل: از طریق پروکسی ← ") + (VIA_PSI.equals(v) ? L.t("سایفون") : "WARP"));
        version++;
    }

    /** "پل + سایفون" / "پل + WARP" */
    public static String viaLabel(Context c) { return viaPsiphon(c) ? L.t("پل + سایفون") : L.t("پل + WARP"); }

    /** results of each kind are kept apart: a WARP (MASQUE) pass says nothing about Psiphon and the other way round */
    static String resKey(Context c) { return viaPsiphon(c) ? "bridgeResPsi" : "bridgeRes"; }

    /** v1.8.4 Bridge + Psiphon: the bridge this session runs on after automatic failover ("" = best / pinned). Never saved. */
    public static volatile String sessionKey = "";

    public static void resetSession() { sessionKey = ""; }

    /** the bridge for this session: the failover choice when set and still known, else best() (the pinned one first) */
    public static JSONObject sessionBridge(Context c) {
        String k = sessionKey;
        if (!k.isEmpty()) for (JSONObject o : results(c)) if (addrOf(o.optString("k")).equals(addrOf(k))) return o;
        return best(c);
    }

    /** bridges that passed their last test (best first), for failover; cooling-down ones too (the round decides) */
    public static List<JSONObject> passed(Context c) {
        List<JSONObject> r = new ArrayList<>();
        boolean ir = isIROnly(c);
        for (JSONObject o : results(c)) if (o.optInt("ok", -1) == 1 && allowed(ir, o)) r.add(o);
        return r;
    }

    /** v1.5: use only proxies located in Iran (domestic proxies that can still reach abroad) */
    public static boolean isIROnly(Context c) { return Core.prefs(c).getBoolean("bridgeIR", false); }

    public static void setIROnly(Context c, boolean on) {
        if (on == isIROnly(c)) return;
        // the pool rotation starts over: the next test takes the (filtered) pool from the beginning
        Core.prefs(c).edit().putBoolean("bridgeIR", on).putInt("bridgeOff", 0).apply();
        Core.log(L.t("پل: فقط پروکسی‌های ایران ") + (on ? L.t("روشن") : L.t("خاموش")));
        version++;
    }

    /** pinned bridge key ("scheme://ip:port") or "" = automatic (lowest real delay) */
    public static String pinned(Context c) { return Core.prefs(c).getString("bridgePin", ""); }

    public static void setPinned(Context c, String k) {
        Core.prefs(c).edit().putString("bridgePin", k == null ? "" : k).apply();
        version++;
    }

    public static List<String> userSources(Context c) {
        List<String> l = new ArrayList<>();
        for (String s : Core.prefs(c).getString("bridgeSrcUser", "").split("\n")) {
            s = s.trim();
            if (s.startsWith("http://") || s.startsWith("https://")) l.add(s);
        }
        return l;
    }

    public static void saveUserSources(Context c, List<String> l) {
        StringBuilder sb = new StringBuilder();
        for (String s : l) { if (sb.length() > 0) sb.append('\n'); sb.append(s); }
        Core.prefs(c).edit().putString("bridgeSrcUser", sb.toString()).apply();
    }

    // ------------------------------------------------------------ parsing
    /**
     * Normalises one proxy line to "scheme://[user:pass@]host:port" (scheme auto when not given).
     * Accepts socks5://, socks4://, http(s)://, socks5h://, ip:port, user:pass@ip:port, ip:port:user:pass.
     */
    public static String normalize(String line) {
        String s = line.trim();
        int sp = s.indexOf(' ');
        if (sp > 0) s = s.substring(0, sp);
        if (s.isEmpty() || s.startsWith("#")) return null;
        String scheme = "auto";
        int i = s.indexOf("://");
        if (i >= 0) {
            scheme = s.substring(0, i).toLowerCase(Locale.US);
            s = s.substring(i + 3);
        }
        switch (scheme) {
            case "socks5h": case "socks": scheme = "socks5"; break;
            case "socks4a": scheme = "socks4"; break;
            case "https": scheme = "http"; break;
            case "socks5": case "socks4": case "http": case "auto": break;
            default: return null;
        }
        if (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        String cred = "";
        int at = s.lastIndexOf('@');
        if (at >= 0) {
            cred = s.substring(0, at);
            s = s.substring(at + 1);
        } else {
            String[] p = s.split(":");
            if (p.length == 4) { s = p[0] + ":" + p[1]; cred = p[2] + ":" + p[3]; }
            else if (p.length == 3) s = p[0] + ":" + p[1];
        }
        int c = s.lastIndexOf(':');
        if (c <= 0) return null;
        String host = s.substring(0, c), port = s.substring(c + 1);
        if (!host.matches("[A-Za-z0-9.\\-\\[\\]:]+") || !port.matches("[0-9]{1,5}")) return null;
        int pn = Integer.parseInt(port);
        if (pn <= 0 || pn > 65535) return null;
        return scheme + "://" + (cred.isEmpty() ? "" : cred + "@") + host + ":" + pn;
    }

    /** "scheme://ip:port" without credentials */
    public static String keyOf(String url) {
        int i = url.indexOf("://");
        String scheme = i > 0 ? url.substring(0, i) : "auto";
        String rest = i > 0 ? url.substring(i + 3) : url;
        int at = rest.lastIndexOf('@');
        if (at >= 0) rest = rest.substring(at + 1);
        return scheme + "://" + rest;
    }

    public static String addrOf(String keyOrUrl) {
        String k = keyOf(keyOrUrl);
        return k.substring(k.indexOf("://") + 3);
    }

    public static boolean hasAuth(String url) {
        String rest = url.substring(url.indexOf("://") + 3);
        return rest.contains("@");
    }

    /** url with the (possibly detected) scheme replaced */
    static String withScheme(String url, String scheme) {
        int i = url.indexOf("://");
        return scheme + "://" + (i > 0 ? url.substring(i + 3) : url);
    }

    // ------------------------------------------------------------ files
    static File userFile(Context c) { return new File(c.getFilesDir(), "bridges_user.txt"); }
    static File poolFile(Context c) { return new File(c.getFilesDir(), "bridges_pool.txt"); }

    static List<String> readLines(File f) {
        List<String> l = new ArrayList<>();
        try {
            if (f.exists()) for (String s : new String(O76App.readAll(f), StandardCharsets.UTF_8).split("\n")) {
                s = s.trim();
                if (!s.isEmpty()) l.add(s);
            }
        } catch (Exception ignored) { }
        return l;
    }

    static void writeLines(File f, List<String> l) {
        StringBuilder sb = new StringBuilder();
        for (String s : l) sb.append(s).append('\n');
        try (FileOutputStream o = new FileOutputStream(f)) {
            o.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            Core.log("bridge file: " + e.getMessage());
        }
    }

    public static List<String> userList(Context c) { return readLines(userFile(c)); }
    public static int poolSize(Context c) { return readLines(poolFile(c)).size(); }

    /** Adds pasted proxies (one per line). Returns how many new ones were added. */
    public static int addPasted(Context c, String text) {
        synchronized (LOCK) {
            List<String> l = userList(c);
            Set<String> have = new HashSet<>();
            for (String u : l) have.add(addrOf(u));
            int n = 0;
            for (String line : text.split("[\\r\\n,;]+")) {
                String u = normalize(line);
                if (u == null || !have.add(addrOf(u))) continue;
                l.add(u);
                n++;
            }
            writeLines(userFile(c), l);
            version++;
            return n;
        }
    }

    public static void clearAll(Context c) {
        synchronized (LOCK) {
            writeLines(userFile(c), new ArrayList<>());
            writeLines(poolFile(c), new ArrayList<>());
            Core.prefs(c).edit().putString("bridgeRes", "[]").putString("bridgeResPsi", "[]").putInt("bridgeOff", 0).putString("bridgePin", "").putString("bridgePoolCC", "").apply();
            version++;
        }
    }

    // ------------------------------------------------------------ results
    public static List<JSONObject> results(Context c) { return results(c, resKey(c)); }

    static List<JSONObject> results(Context c, String key) {
        List<JSONObject> l = new ArrayList<>();
        try {
            JSONArray a = new JSONArray(Core.prefs(c).getString(key, "[]"));
            for (int i = 0; i < a.length(); i++) {
                JSONObject o = a.optJSONObject(i);
                if (o != null && !o.optString("k").isEmpty()) l.add(o);
            }
        } catch (Exception ignored) { }
        sort(l);
        return l;
    }

    /**
     * 0 working + reaches abroad (intl 1 or unknown), 1 working but domestic-only (intl 0), 2 untested,
     * 3 working but cooling down after a failure, 4 failed.
     */
    private static int rank(JSONObject o) {
        int ok = o.optInt("ok", -1);
        if (ok == 1) return coolingDown(o) ? 3 : (intl(o) == 0 ? 1 : 0);
        if (ok == -1) return 2;
        return 4;
    }

    /** v1.5: with "IR only", only bridges tested in that mode (tagged cc=IR) are picked automatically */
    static boolean allowed(boolean irOnly, JSONObject o) {
        return !irOnly || "IR".equals(o.optString("cc"));
    }

    /** v1.5 BINTL result: 1 reached a server abroad, 0 domestic-only, -1 unknown */
    public static int intl(JSONObject o) { return o.optInt("intl", -1); }

    /** intl=1 before unknown before intl=0 */
    private static int intlTier(JSONObject o) {
        int i = intl(o);
        return i == 1 ? 0 : i == -1 ? 1 : 2;
    }

    /**
     * v1.4 score (lower = better): real delay + slow-download penalty, divided by the smoothed success rate
     * (sc = real passes / successful connections, fc = failures), plus a small penalty for colos far from Iran.
     */
    public static long score(JSONObject o) {
        long rms = o.optLong("rms", 0);
        if (rms <= 0) rms = 9999;
        long kb = o.optLong("kbps", 0);
        if (kb > 0 && kb < 50) rms += (50 - kb) * 10;
        return Core.stabilityScore(rms, o.optInt("sc", 0), o.optInt("fc", 0)) + Core.coloPenalty(o.optString("colo", ""));
    }

    public static void sort(List<JSONObject> l) {
        Collections.sort(l, (x, y) -> {
            int r = Integer.compare(rank(x), rank(y));
            if (r != 0) return r;
            r = Integer.compare(intlTier(x), intlTier(y));
            if (r != 0) return r;
            if (rank(x) != 2 && rank(x) != 4) return Long.compare(score(x), score(y));
            return Long.compare(x.optLong("hs", 99999), y.optLong("hs", 99999));
        });
    }

    static boolean coolingDown(JSONObject o) {
        long ft = o.optLong("ft", 0);
        return ft > 0 && System.currentTimeMillis() - ft < FAIL_COOLDOWN_MS;
    }

    private static void saveResults(Context c, List<JSONObject> l) { saveResults(c, l, resKey(c)); }

    private static void saveResults(Context c, List<JSONObject> l, String key) {
        sort(l);
        JSONArray a = new JSONArray();
        int n = 0;
        for (JSONObject o : l) { if (n++ >= 300) break; a.put(o); }
        Core.prefs(c).edit().putString(key, a.toString()).apply();
        version++;
    }

    /** merges by ip:port */
    static void merge(Context c, List<JSONObject> news) { merge(c, news, resKey(c)); }

    static void merge(Context c, List<JSONObject> news, String key) {
        synchronized (LOCK) {
            Map<String, JSONObject> m = new LinkedHashMap<>();
            for (JSONObject o : results(c, key)) m.put(addrOf(o.optString("k")), o);
            for (JSONObject o : news) {
                String a = addrOf(o.optString("k"));
                JSONObject x = m.get(a);
                int ok = o.optInt("ok", -1);
                try {
                    if (x == null) { x = new JSONObject(); m.put(a, x); }
                    java.util.Iterator<String> it = o.keys();
                    while (it.hasNext()) { String k = it.next(); x.put(k, o.get(k)); }
                    if (ok == 1) { x.remove("ft"); x.put("sc", x.optInt("sc", 0) + 1); }
                    else if (ok == 0) x.put("fc", x.optInt("fc", 0) + 1);
                } catch (Exception ignored) { }
            }
            saveResults(c, new ArrayList<>(m.values()), key);
        }
    }

    public static void remove(Context c, String key) {
        synchronized (LOCK) {
            String a = addrOf(key);
            List<JSONObject> l = new ArrayList<>();
            for (JSONObject o : results(c)) if (!addrOf(o.optString("k")).equals(a)) l.add(o);
            saveResults(c, l);
            List<String> u = new ArrayList<>();
            for (String s : userList(c)) if (!addrOf(s).equals(a)) u.add(s);
            writeLines(userFile(c), u);
            if (addrOf(pinned(c)).equals(a)) setPinned(c, "");
        }
    }

    /** a successful connection through this bridge: success counter + clears cooldown */
    public static void markOk(Context c, String key) {
        if (key == null || key.isEmpty()) return;
        JSONObject f = new JSONObject();
        try { f.put("k", key).put("ok", 1).put("t", System.currentTimeMillis()); } catch (Exception ignored) { }
        List<JSONObject> one = new ArrayList<>();
        one.add(f);
        merge(c, one);
    }

    /** v1.8.4: a WARP-kind bridge (Aether / warp-plus over a bridge) failed, whatever the bridge screen's choice */
    public static void markFailedKeyWarp(Context c, String key) {
        if (key == null || key.isEmpty()) return;
        JSONObject f = new JSONObject();
        try { f.put("k", key).put("ok", 0).put("ft", System.currentTimeMillis()).put("t", System.currentTimeMillis()); } catch (Exception ignored) { }
        List<JSONObject> one = new ArrayList<>();
        one.add(f);
        merge(c, one, "bridgeRes");
    }

    public static void markFailedKey(Context c, String key) {
        if (key == null || key.isEmpty()) return;
        JSONObject f = new JSONObject();
        try { f.put("k", key).put("ok", 0).put("ft", System.currentTimeMillis()).put("t", System.currentTimeMillis()); } catch (Exception ignored) { }
        List<JSONObject> one = new ArrayList<>();
        one.add(f);
        merge(c, one);
    }

    public static void markFailed(Context c, JSONObject b) {
        if (b == null) return;
        JSONObject f = new JSONObject();
        try { f.put("k", b.optString("k")).put("ok", 0).put("ft", System.currentTimeMillis()).put("t", System.currentTimeMillis()); }
        catch (Exception ignored) { }
        List<JSONObject> one = new ArrayList<>();
        one.add(f);
        merge(c, one);
    }

    /** v1.4: urls of up to n other working bridges (best first) kept warm by the core for instant failover */
    public static List<String> warmSet(Context c, String excludeKey, int n) {
        List<String> r = new ArrayList<>();
        String ex = excludeKey == null ? "" : addrOf(excludeKey);
        boolean ir = isIROnly(c);
        for (JSONObject o : results(c)) {
            if (r.size() >= n) break;
            if (o.optInt("ok", -1) != 1 || coolingDown(o) || intl(o) == 0 || !allowed(ir, o)) continue;
            if (addrOf(o.optString("k")).equals(ex)) continue;
            r.add(o.optString("u", o.optString("k")));
        }
        return r;
    }

    /**
     * v1.5.1 WARP registration routes: up to n working bridges that reached a server abroad (intl=1 first, then
     * unknown), regardless of the IR-only switch (Iranian proxies that reach abroad are often the best way to
     * api.cloudflareclient.com). Cooling-down ones are skipped.
     */
    public static List<String> registerSet(Context c, int n) {
        List<String> r = new ArrayList<>();
        for (int pass = 0; pass < 2 && r.size() < n; pass++) {
            for (JSONObject o : results(c, "bridgeRes")) { // v1.8.4: WARP-tested bridges
                if (r.size() >= n) break;
                if (o.optInt("ok", -1) != 1 || coolingDown(o)) continue;
                int in = intl(o);
                if (pass == 0 ? in != 1 : in != -1) continue;
                String u = o.optString("u", o.optString("k"));
                if (!u.isEmpty() && !r.contains(u)) r.add(u);
            }
        }
        return r;
    }

    public static int workingCount(Context c) {
        int n = 0;
        boolean ir = isIROnly(c);
        for (JSONObject o : results(c)) if (o.optInt("ok", -1) == 1 && !coolingDown(o) && allowed(ir, o)) n++;
        return n;
    }

    /** Best bridge to use: the pinned one, else lowest real delay among recently passed ones (not cooling down). */
    public static JSONObject best(Context c) {
        List<JSONObject> l = results(c);
        String pin = pinned(c);
        if (!pin.isEmpty()) {
            for (JSONObject o : l) if (addrOf(o.optString("k")).equals(addrOf(pin))) return o;
        }
        boolean ir = isIROnly(c);
        for (JSONObject o : l) {
            if (o.optInt("ok", -1) != 1 || coolingDown(o) || !allowed(ir, o)) continue;
            return o;
        }
        return null;
    }

    // ------------------------------------------------------------ fetch lists
    public static void startFetch(Context ctx, Runnable done) {
        final Context c = ctx.getApplicationContext();
        synchronized (LOCK) {
            if (busy) return;
            busy = true;
            stopReq = false;
        }
        new Thread(() -> {
            try { fetch(c); } finally { busy = false; proc = null; version++; if (done != null) done.run(); }
            O76VpnService.bridgesUpdated(c);
        }, "o76-bfetch").start();
    }

    /** Downloads the public lists (direct connection; may be filtered in Iran) into the pool. Blocking. */
    public static int fetch(Context c) {
        final boolean ir = isIROnly(c);
        status = ir ? L.t("دریافت فهرست پروکسی‌های ایران …") : L.t("دریافت فهرست پروکسی‌ها از اینترنت …");
        StringBuilder src = new StringBuilder();
        if (ir) for (String s : IR_SOURCES) { if (src.length() > 0) src.append('\n'); src.append(s); }
        for (String s : DEFAULT_SOURCES) { if (src.length() > 0) src.append('\n'); src.append(s); }
        for (String s : userSources(c)) src.append('\n').append("auto|").append(s);
        final List<String> got = new ArrayList<>();
        final int[] okSrc = {0}, badSrc = {0};
        try {
            List<String> fa = new ArrayList<>(java.util.Arrays.asList("fetchlists", "-urls", src.toString(), "-max", "4000", "-per", "1500", "-t", "20s"));
            if (ir) { fa.add("-country"); fa.add("IR"); }
            Process p = Core.start(c, fa.toArray(new String[0]));
            proc = p;
            Core.pump(p, line -> {
                if (line.startsWith("P ")) got.add(line.substring(2).trim());
                else if (line.startsWith("SRC ok")) okSrc[0]++;
                else if (line.startsWith("SRC err")) { badSrc[0]++; Core.log(L.t("فهرست پروکسی: ") + line.substring(8)); }
            });
        } catch (Exception e) {
            Core.log("fetchlists: " + e);
        }
        Core.prefs(c).edit().putString("bridgeFetchInfo", okSrc[0] + "/" + (okSrc[0] + badSrc[0]) + " sources, "
                + got.size() + " proxies" + (ir ? " (IR)" : "") + " @" + System.currentTimeMillis()).apply();
        if (got.isEmpty()) {
            status = L.t("دریافت فهرست ناموفق بود (") + badSrc[0] + L.t(" منبع در دسترس نبود — احتمالاً فیلتر). پروکسی‌ها را دستی «بچسبانید».");
            Core.log(status);
            return 0;
        }
        synchronized (LOCK) {
            writeLines(poolFile(c), got);
            // v1.5: "IR" = this pool was fetched with -country IR (already geo-checked; trusted IR sources kept as is)
            Core.prefs(c).edit().putString("bridgePoolCC", ir ? "IR" : "").putInt("bridgeOff", 0).putLong("bridgeFetchAt", System.currentTimeMillis()).apply();
        }
        status = L.t("فهرست به‌روز شد: ") + got.size() + L.t(" پروکسی از ") + okSrc[0] + L.t(" منبع") + (badSrc[0] > 0 ? " (" + badSrc[0] + L.t(" منبع ناموفق)") : "");
        Core.log(status);
        return got.size();
    }

    /**
     * v1.5: keeps only the proxies located in Iran (bundled IP ranges, "o76core ipfilter -country IR"). Lines are fed
     * on stdin (they may contain credentials: never logged). Returns null when the filter could not run.
     */
    static List<String> ipFilterIR(Context c, final List<String> lines) {
        final List<String> out = new ArrayList<>();
        final boolean[] done = {false};
        try {
            final Process p = Core.start(c, "ipfilter", "-country", "IR");
            Thread w = new Thread(() -> {
                try (java.io.OutputStream os = p.getOutputStream()) {
                    StringBuilder sb = new StringBuilder();
                    for (String l : lines) sb.append(l).append('\n');
                    os.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                    os.flush();
                } catch (Exception ignored) { }
            }, "o76-ipfilter");
            w.start();
            Core.pump(p, line -> {
                if (line.equals("DONE")) done[0] = true;
                else if (!line.startsWith("ERR")) out.add(line);
                else Core.log("ipfilter: " + line);
            });
        } catch (Exception e) {
            Core.log("ipfilter: " + e);
            return null;
        }
        return done[0] ? out : null;
    }

    // ------------------------------------------------------------ test
    public static void stop() {
        stopReq = true;
        Process p = proc;
        if (p != null) p.destroy();
    }

    public static void startTest(Context ctx, Runnable done) {
        final Context c = ctx.getApplicationContext();
        synchronized (LOCK) {
            if (busy) return;
            busy = true;
            stopReq = false;
        }
        new Thread(() -> {
            try { test(c, MAX_TEST); } finally { busy = false; proc = null; version++; if (done != null) done.run(); }
            O76VpnService.bridgesUpdated(c);
        }, "o76-btest").start();
    }

    /** MASQUE HTTP/2 endpoints used through bridges (port 443: HTTP proxies usually only CONNECT to 443). */
    static String testEndpoints(Context c) {
        List<String> snis = Core.snis(c);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(3, snis.size()); i++) {
            if (sb.length() > 0) sb.append(';');
            sb.append("h2|").append(Core.DEFAULT_EP).append('|').append(snis.get(i));
        }
        return sb.toString();
    }

    /**
     * Tests up to max proxies: previously working first, then pasted ones, then the next slice of the downloaded
     * pool (rotating offset so every run tries new ones). Blocking. Returns the number that passed the real test.
     */
    public static int test(Context c, int max) {
        return test(c, max, max, 16, 10);
    }

    /**
     * v1.4 background re-test while connected (~every 20 min): the known-good bridges plus a few new ones from the
     * pool, so stability counters and the warm standby set stay fresh. Blocking.
     */
    public static int retest(Context c) {
        synchronized (LOCK) {
            if (busy) return -1;
            busy = true;
            stopReq = false;
        }
        try { return viaPsiphon(c) ? -1 : test(c, 60, 30, 10, 8); } finally { busy = false; proc = null; version++; }
    }

    public static int test(Context c, int max, int poolTake, int realN, int keep) {
        final boolean ir = isIROnly(c);
        final boolean psi = viaPsiphon(c); // v1.8.4: Psiphon test, no WARP account needed
        // v1.8.2: the bridge test runs a real MASQUE tunnel through each proxy, so it needs the WARP account
        if (!psi && !Core.hasConfig(c)) {
            status = L.t("اول حساب WARP لازم است: در صفحهٔ اصلی «ثبت‌نام WARP» را بزنید (یا کانفیگ وارد کنید)، بعد پل‌ها را تست کنید.");
            Core.log(status);
            return 0;
        }
        // build the candidate list: url per ip:port
        LinkedHashMap<String, String> cand = new LinkedHashMap<>();
        Map<String, String> userUrl = new HashMap<>();
        for (String u : userList(c)) userUrl.put(addrOf(u), u);
        for (JSONObject o : results(c)) {
            if (o.optInt("ok", -1) == 1 && cand.size() < 40) {
                String a = addrOf(o.optString("k"));
                cand.put(a, userUrl.containsKey(a) ? userUrl.get(a) : o.optString("u", o.optString("k")));
            }
        }
        for (String u : userList(c)) if (cand.size() < max && !cand.containsKey(addrOf(u))) cand.put(addrOf(u), u);
        List<String> pool = readLines(poolFile(c));
        if (ir && !pool.isEmpty() && !"IR".equals(Core.prefs(c).getString("bridgePoolCC", ""))) {
            // v1.5: the pool was fetched before "IR only" was switched on -> keep its Iranian part once
            List<String> f = ipFilterIR(c, pool);
            if (f != null) {
                Core.log(L.t("فقط ایران: ") + f.size() + L.t(" از ") + pool.size() + L.t(" پروکسی فهرست در ایران است"));
                pool = f;
                synchronized (LOCK) {
                    writeLines(poolFile(c), pool);
                    Core.prefs(c).edit().putString("bridgePoolCC", "IR").putInt("bridgeOff", 0).apply();
                }
            }
        }
        int off = Core.prefs(c).getInt("bridgeOff", 0);
        if (off >= pool.size()) off = 0;
        int taken = 0;
        if (psi) { max = Math.min(max, PSI_MAX); poolTake = Math.min(poolTake, PSI_MAX); }
        for (int i = 0; i < pool.size() && cand.size() < max && taken < poolTake; i++) {
            String u = pool.get((off + i) % pool.size());
            if (!cand.containsKey(addrOf(u))) { cand.put(addrOf(u), u); taken++; }
        }
        Core.prefs(c).edit().putInt("bridgeOff", pool.isEmpty() ? 0 : (off + taken) % Math.max(1, pool.size())).apply();
        if (ir && !cand.isEmpty()) {
            // v1.5 IR only: "ipfilter -country IR" on every candidate that is not known to be Iranian already
            // (pasted ones are the user's choice; a pool fetched with -country IR was checked by fetchlists, whose
            // trusted IR-only sources may list IPs outside the bundled ranges)
            boolean poolIR = "IR".equals(Core.prefs(c).getString("bridgePoolCC", ""));
            Set<String> poolA = new HashSet<>();
            if (poolIR) for (String u : pool) poolA.add(addrOf(u));
            List<String> check = new ArrayList<>();
            for (Map.Entry<String, String> e : cand.entrySet())
                if (!userUrl.containsKey(e.getKey()) && !poolA.contains(e.getKey())) check.add(e.getValue());
            List<String> keepL = check.isEmpty() ? check : ipFilterIR(c, check);
            if (keepL != null && keepL.size() != check.size()) {
                Set<String> keepA = new HashSet<>();
                for (String u : keepL) keepA.add(addrOf(u));
                java.util.Iterator<Map.Entry<String, String>> it = cand.entrySet().iterator();
                while (it.hasNext()) {
                    String a = it.next().getKey();
                    if (!userUrl.containsKey(a) && !poolA.contains(a) && !keepA.contains(a)) it.remove();
                }
                Core.log(L.t("فقط ایران: ") + (check.size() - keepL.size()) + L.t(" پروکسی خارج از ایران کنار گذاشته شد"));
            }
        }
        if (cand.isEmpty()) {
            status = L.t("فهرست پل خالی است — «به‌روزرسانی فهرست‌ها» یا «چسباندن پروکسی» را بزنید.");
            return 0;
        }
        if (psi) return testPsi(c, cand, ir);
        final Map<String, String> urlByAddr = new HashMap<>(cand);
        File in = new File(c.getCacheDir(), "bridgetest.txt");
        writeLines(in, new ArrayList<>(cand.values()));
        final int total = cand.size();
        status = L.t("تست ") + total + L.t(" پروکسی (") + CONC + L.t(" هم‌زمان) …");
        Core.log(L.t("تست پل: ") + total + L.t(" پروکسی") + L.t(" (نوع WARP)") + (ir ? L.t(" — فقط ایران") : ""));
        final Map<String, Integer> intlRes = Collections.synchronizedMap(new HashMap<>());
        final int[] intlN = {0, 0};
        final List<JSONObject> res = Collections.synchronizedList(new ArrayList<>());
        final int[] passed = {0}, hsOk = {0};
        final long now = System.currentTimeMillis();
        final Set<String> testedReal = new HashSet<>();
        try {
            List<String> args = new ArrayList<>();
            args.add("bridgetest");
            args.add("-proxies"); args.add(in.getAbsolutePath());
            args.add("-c"); args.add(Core.cfg(c).getAbsolutePath());
            args.add("-eps"); args.add(testEndpoints(c));
            args.add("-n"); args.add(String.valueOf(CONC));
            args.add("-max"); args.add(String.valueOf(max));
            args.add("-t"); args.add("6s");
            args.add("-real"); args.add(String.valueOf(realN));
            args.add("-keep"); args.add(String.valueOf(keep));
            args.add("-dl"); args.add("100000");
            args.addAll(Core.dpiArgs(c));
            Process p = Core.start(c, args.toArray(new String[0]));
            proc = p;
            Core.pump(p, line -> {
                String[] s = line.split(" ");
                try {
                    if (line.startsWith("BPROG ") && s.length >= 3) {
                        hsOk[0] = Integer.parseInt(s[2]);
                        status = L.t("مرحلهٔ ۱ (اتصال پروکسی + هندشیک MASQUE): ") + s[1] + L.t(" از ") + total + L.t(" — موفق: ") + s[2];
                    } else if (line.startsWith("BSTAGE2 ")) {
                        status = L.t("مرحلهٔ ۲: تست واقعی (warp=on + دانلود) روی ") + s[1] + L.t(" پروکسی سریع‌تر …");
                    } else if (line.startsWith("BINTL ") && s.length >= 3) {
                        // v1.5: 1 = the proxy reached a server abroad, 0 = it answered but only reaches Iran
                        String a = addrOf(s[1]);
                        boolean yes = "1".equals(s[2]);
                        Integer prev = intlRes.get(a);
                        if (prev == null || yes) intlRes.put(a, yes ? 1 : 0);
                        if (yes) { intlN[0]++; Core.log(line); } else intlN[1]++;
                    } else if (line.startsWith("BHS ") && s.length >= 3) {
                        JSONObject o = mk(s[1], urlByAddr, now);
                        o.put("hs", Long.parseLong(s[2])).put("ok", -1);
                        res.add(o);
                    } else if (line.startsWith("BREAL ") && s.length >= 9) {
                        JSONObject o = mk(s[1], urlByAddr, now);
                        o.put("ok", 1).put("ep", s[2]).put("sni", s[3]).put("rms", Long.parseLong(s[4]))
                                .put("kbps", Long.parseLong(s[5])).put("hs", Long.parseLong(s[7])).put("rt", now);
                        if (s.length >= 9) o.put("colo", s[8]);
                        res.add(o);
                        testedReal.add(addrOf(s[1]));
                        passed[0]++;
                        Core.log(L.t("✓ پل ") + s[1] + L.t(" تاخیر واقعی ") + s[4] + L.t("ms، ") + s[5] + " KB/s (" + (s.length >= 9 ? s[8] : "") + ")");
                        status = L.t("مرحلهٔ ۲: ") + passed[0] + L.t(" پل سالم پیدا شد …");
                    } else if (line.startsWith("BFAIL ") && s.length >= 3) {
                        JSONObject o = mk(s[1], urlByAddr, now);
                        o.put("ok", 0).put("ft", now);
                        res.add(o);
                        testedReal.add(addrOf(s[1]));
                    } else if (line.startsWith("ERR")) {
                        Core.log(line);
                    }
                } catch (Exception ignored) { }
            });
        } catch (Exception e) {
            Core.log("bridgetest: " + e);
        }
        if (intlN[0] + intlN[1] > 0)
            Core.log("BINTL: " + intlN[0] + L.t(" پروکسی به خارج می‌رسد، ") + intlN[1] + L.t(" فقط داخلی"));
        // previously-working bridges that failed stage 1 this time -> failed
        List<JSONObject> l;
        synchronized (res) { l = new ArrayList<>(res); }
        Set<String> seen = new HashSet<>();
        for (JSONObject o : l) seen.add(addrOf(o.optString("k")));
        if (!stopReq) {
            for (JSONObject o : results(c)) {
                String a = addrOf(o.optString("k"));
                if (cand.containsKey(a) && !seen.contains(a)) {
                    JSONObject f = new JSONObject();
                    try { f.put("k", o.optString("k")).put("ok", 0).put("ft", now).put("t", now); } catch (Exception ignored) { }
                    l.add(f);
                }
            }
        }
        // a handshake-only result must not overwrite an older real pass that was not re-tested
        List<JSONObject> fin = new ArrayList<>();
        for (JSONObject o : l) {
            if (o.optInt("ok", -1) == -1 && testedReal.contains(addrOf(o.optString("k")))) continue;
            fin.add(o);
        }
        // v1.5: kind of test and international reach on every result; a real pass proves reach abroad
        Set<String> inFin = new HashSet<>();
        for (JSONObject o : fin) {
            String a = addrOf(o.optString("k"));
            inFin.add(a);
            try {
                Integer in2 = intlRes.get(a);
                if (o.optInt("ok", -1) == 1) o.put("intl", 1);
                else if (in2 != null) o.put("intl", in2.intValue());
                if (o.has("hs") || o.has("rms")) {
                    o.put("kind", "m");
                    o.put("cc", ir ? "IR" : ""); // tested under "IR only" (Iranian, or pasted by the user)
                }
            } catch (Exception ignored) { }
        }
        synchronized (intlRes) {
            for (Map.Entry<String, Integer> e : intlRes.entrySet()) {
                if (inFin.contains(e.getKey())) continue;
                // proxies that only answered BINTL (e.g. domestic-only, failed stage 1) and are already known
                for (JSONObject o : results(c)) {
                    if (!addrOf(o.optString("k")).equals(e.getKey())) continue;
                    JSONObject u = new JSONObject();
                    try { u.put("k", o.optString("k")).put("intl", e.getValue().intValue()); } catch (Exception ignored) { }
                    fin.add(u);
                    break;
                }
            }
        }
        merge(c, fin);
        Core.prefs(c).edit().putLong("bridgeTestAt", now).apply();
        status = passed[0] > 0
                ? L.t("تست پل تمام شد: ") + passed[0] + L.t(" پل سالم (از ") + total + L.t(" پروکسی، ") + hsOk[0] + L.t(" هندشیک موفق)")
                : L.t("تست پل: هیچ پلی تست واقعی را رد نکرد (") + hsOk[0] + L.t(" از ") + total + L.t(" فقط هندشیک). دوباره «تست» بزنید تا پروکسی‌های بعدی فهرست امتحان شوند.");
        Core.log(status);
        return passed[0];
    }

    /**
     * v1.8.4 Bridge + Psiphon test ("libchain ptest"): proxy handshake (+ TLS to a host abroad through it) on every
     * candidate, then a real Psiphon connect through the fastest ones, 3 at a time (75 s each). No WARP account.
     * Results go to the Psiphon result list; each one keeps its latency or its error ("e").
     */
    static int testPsi(Context c, LinkedHashMap<String, String> cand, boolean ir) {
        if (!Chain.available(c)) {
            status = L.t("هستهٔ سایفون (libchain) روی این گوشی نیست");
            return 0;
        }
        final List<String> urls = new ArrayList<>(cand.values());
        File in = new File(Chain.dir(c), "ptest.txt");
        writeLines(in, urls); // may contain credentials: app-private, deleted below, never logged
        final int total = urls.size();
        final long now = System.currentTimeMillis();
        final List<JSONObject> res = Collections.synchronizedList(new ArrayList<>());
        final Map<Integer, String> scheme = Collections.synchronizedMap(new HashMap<>());
        final Map<Integer, Long> hsMs = Collections.synchronizedMap(new HashMap<>());
        final int[] passed = {0}, hsOk = {0}, stage2 = {0}, tried = {0};
        status = L.t("سایفون: تست ") + total + L.t(" پروکسی (هندشیک) …");
        Core.log(L.t("تست پل: ") + total + L.t(" پروکسی") + L.t(" (نوع سایفون)") + (ir ? L.t(" — فقط ایران") : ""));
        try {
            List<String> a = new ArrayList<>();
            a.add("ptest"); a.add("-file"); a.add(in.getAbsolutePath());
            a.add("-n"); a.add(String.valueOf(PSI_CONC)); a.add("-hs"); a.add("6");
            a.add("-real"); a.add(String.valueOf(PSI_REAL)); a.add("-par"); a.add(String.valueOf(PSI_PAR));
            a.add("-keep"); a.add(String.valueOf(PSI_KEEP)); a.add("-timeout"); a.add(String.valueOf(PSI_TIMEOUT));
            a.add("-dir"); a.add(Chain.dir(c).getAbsolutePath());
            a.add("-dns"); a.add(Core.systemDns(c));
            if (!Chain.region(c).isEmpty()) { a.add("-region"); a.add(Chain.region(c)); }
            Process p = Chain.start(c, a, false);
            proc = p;
            Core.pump(p, line -> {
                String[] s = line.split(" ", 4);
                try {
                    if (line.startsWith("PPROG ") && s.length >= 3) {
                        hsOk[0] = Integer.parseInt(s[2]);
                        status = L.t("سایفون — مرحلهٔ ۱ (هندشیک پروکسی): ") + s[1] + L.t(" از ") + total + L.t(" — موفق: ") + s[2];
                    } else if (line.startsWith("PHS ") && s.length >= 4) {
                        int i = Integer.parseInt(s[1]);
                        scheme.put(i, s[3].trim());
                        hsMs.put(i, Long.parseLong(s[2]));
                        JSONObject o = mkPsi(urls, i, s[3].trim(), now);
                        o.put("hs", Long.parseLong(s[2])).put("ok", -1);
                        res.add(o);
                    } else if (line.startsWith("PSTAGE2 ")) {
                        stage2[0] = Integer.parseInt(s[1].trim());
                        status = L.t("سایفون — مرحلهٔ ۲: اتصال واقعی سایفون از طریق ") + stage2[0] + L.t(" پروکسی سریع‌تر (۳ هم‌زمان، تا ۷۵ ثانیه) …");
                    } else if (line.startsWith("PTRY ")) {
                        tried[0]++;
                    } else if (line.startsWith("PREAL ") && s.length >= 3) {
                        int i = Integer.parseInt(s[1]);
                        JSONObject o = mkPsi(urls, i, scheme.get(i), now);
                        Long h = hsMs.get(i);
                        o.put("ok", 1).put("rms", Long.parseLong(s[2])).put("rt", now).put("e", "");
                        if (h != null) o.put("hs", h.longValue());
                        if (s.length >= 4) o.put("colo", s[3].trim());
                        res.add(o);
                        passed[0]++;
                        Core.log(L.t("✓ پل ") + o.optString("k") + L.t(" سایفون وصل شد، تاخیر واقعی ") + s[2] + "ms" + (s.length >= 4 ? " (" + s[3].trim() + ")" : ""));
                        status = L.t("سایفون — مرحلهٔ ۲: ") + passed[0] + L.t(" پل سالم پیدا شد …");
                    } else if (line.startsWith("PFAIL ") && s.length >= 3) {
                        int i = Integer.parseInt(s[1]);
                        boolean real = "psiphon".equals(s[2]);
                        JSONObject o = mkPsi(urls, i, scheme.get(i), now);
                        o.put("ok", 0).put("e", (real ? L.t("سایفون: ") : L.t("هندشیک: ")) + (s.length >= 4 ? s[3] : ""));
                        if (real) {
                            Long h = hsMs.get(i);
                            if (h != null) o.put("hs", h.longValue());
                            Core.log(L.t("✗ پل ") + o.optString("k") + " — " + o.optString("e"));
                        }
                        res.add(o);
                    } else if (line.startsWith("ERR")) {
                        Core.log("ptest: " + line);
                    }
                } catch (Exception ignored) { }
            });
        } catch (Exception e) {
            Core.log("ptest: " + e);
        } finally {
            //noinspection ResultOfMethodCallIgnored
            in.delete();
        }
        List<JSONObject> fin;
        synchronized (res) { fin = new ArrayList<>(res); }
        for (JSONObject o : fin) {
            try {
                if (o.optInt("ok", -1) == 1) o.put("intl", 1);
                o.put("kind", "p");
                o.put("cc", ir ? "IR" : "");
            } catch (Exception ignored) { }
        }
        if (stopReq) { // stopped: keep only what finished
            List<JSONObject> f2 = new ArrayList<>();
            for (JSONObject o : fin) if (o.optInt("ok", -1) != 0 || o.optString("e").startsWith(L.t("سایفون: "))) f2.add(o);
            fin = f2;
        }
        merge(c, fin);
        Core.prefs(c).edit().putLong("bridgeTestAtPsi", now).apply();
        status = passed[0] > 0
                ? L.t("تست پل (سایفون) تمام شد: ") + passed[0] + L.t(" پل سالم (از ") + total + L.t(" پروکسی، ") + hsOk[0] + L.t(" هندشیک موفق)")
                : L.t("تست پل (سایفون): هیچ پلی به سایفون وصل نشد (") + hsOk[0] + L.t(" از ") + total + L.t(" فقط هندشیک). دوباره «تست» بزنید تا پروکسی‌های بعدی فهرست امتحان شوند.");
        Core.log(status);
        return passed[0];
    }

    /** result object for line i of the ptest file; the detected scheme replaces "auto" */
    private static JSONObject mkPsi(List<String> urls, int i, String detected, long now) throws Exception {
        String u = i >= 0 && i < urls.size() ? urls.get(i) : "auto://0.0.0.0:0";
        if (detected != null && !detected.isEmpty() && u.startsWith("auto://")) u = withScheme(u, detected);
        JSONObject o = new JSONObject();
        o.put("k", keyOf(u)).put("u", u).put("t", now);
        return o;
    }

    private static JSONObject mk(String key, Map<String, String> urlByAddr, long now) throws Exception {
        JSONObject o = new JSONObject();
        String a = addrOf(key);
        String scheme = key.substring(0, key.indexOf("://"));
        String u = urlByAddr.get(a);
        if (u == null) u = key;
        if (!"auto".equals(scheme)) u = withScheme(u, scheme);
        o.put("k", key).put("t", now);
        if (hasAuth(u)) o.put("u", u); // credentials stay in app storage only, never in logs
        else o.put("u", key);
        return o;
    }

    /** text for the diagnostic report: no credentials */
    public static String diag(Context c) {
        StringBuilder sb = new StringBuilder();
        sb.append("bridge: ").append(enabled(c) ? "ON" : "off").append(" via=").append(via(c)).append(" irOnly=").append(isIROnly(c))
                .append(" pinned=").append(pinned(c).isEmpty() ? "-" : pinned(c))
                .append(" user=").append(userList(c).size()).append(" pool=").append(poolSize(c))
                .append(" fetch=").append(Core.prefs(c).getString("bridgeFetchInfo", "never"))
                .append(" working=").append(workingCount(c)).append('\n');
        long t = Core.prefs(c).getLong("bridgeTestAt", 0);
        sb.append("bridgeTest: ").append(t == 0 ? "never" : ((System.currentTimeMillis() - t) / 60000) + " min ago").append('\n');
        int n = 0;
        for (JSONObject o : results(c)) {
            if (n++ >= 15) break;
            sb.append("  ").append(o.optString("k")).append(hasAuth(o.optString("u", "")) ? " (auth)" : "")
                    .append(" ok=").append(o.optInt("ok", -1)).append(" hs=").append(o.optLong("hs", 0))
                    .append(" rtt=").append(o.optLong("rms", 0)).append(" kbps=").append(o.optLong("kbps", 0))
                    .append(" intl=").append(intl(o)).append(" cc=").append(o.optString("cc", "-")).append(' ').append(o.optString("kind", ""))
                    .append(' ').append(o.optString("colo", ""))
                    .append(o.optString("e", "").isEmpty() ? "" : " err=" + o.optString("e")).append('\n');
        }
        return sb.toString();
    }

    public static String typeLabel(String key) {
        String s = key.substring(0, Math.max(0, key.indexOf("://"))).toUpperCase(Locale.US);
        return s.equals("AUTO") ? "?" : s.equals("HTTP") ? "HTTP" : s;
    }

    private Bridges() {}
}
