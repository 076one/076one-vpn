package com.o76one.app;

import android.content.Context;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Server selection logic shared by the UI and the VPN service:
 * full scan, quick re-probe, choosing the lowest-latency healthy server (HTTP/3 first, HTTP/2 fallback),
 * automatic background re-scan (empty / older than 6 h / current server failing).
 */
public final class Servers {
    public static final long RESCAN_AGE_MS = 6L * 3600 * 1000;
    /** after QUIC failed to connect, go straight to HTTP/2 for this long (the remembered winner) */
    public static final long H3_SKIP_MS = 30L * 60 * 1000;
    /** an entry whose tunnel failed is not auto-picked again for this long */
    public static final long FAIL_COOLDOWN_MS = 10L * 60 * 1000;
    private static final int KEEP_H2 = 45, KEEP_H3 = 20;

    /** What to connect to: an optional HTTP/3 endpoint tried first and an HTTP/2 fallback. */
    public static final class Plan {
        public JSONObject h3, h2;
        public boolean pinned;
        /** v1.3: upstream proxy (url may contain user:pass - never log it; log bridgeKey) */
        public String bridgeUrl, bridgeKey;
        public JSONObject bridge;

        /** v1.6 Aether mode: local SOCKS5 port of the running Aether core; 0 for other plans */
        public int aetherPort;
        /** v1.7: the SOCKS port belongs to the Firefox core (libfpn) instead of Aether */
        public boolean fox;
        /** v1.8: the SOCKS port belongs to warp-plus (libwplus) */
        public boolean wp;
        /** v1.8.2: the SOCKS port belongs to the Config + Psiphon core (libchain) */
        public boolean chain;
        /** v1.4 bridge mode: standby bridge urls kept warm by the core */
        public List<String> standby = new ArrayList<>();

        public String describe() {
            if (aetherPort > 0) return (fox ? "Firefox" : wp ? L.t("وارپ+") : chain ? (bridgeKey != null ? L.t("پل + سایفون") + " " + bridgeKey : L.t("کانفیگ + سایفون")) : "Aether") + " socks 127.0.0.1:" + aetherPort;
            StringBuilder sb = new StringBuilder();
            if (h3 != null) sb.append("h3 ").append(h3.optString("ep")).append(" [").append(h3.optString("sni")).append("]");
            if (h2 != null) {
                if (sb.length() > 0) sb.append(" → ");
                sb.append("h2 ").append(h2.optString("ep")).append(" [").append(h2.optString("sni")).append("]");
            }
            if (bridgeKey != null) sb.append(L.t(" via پل ")).append(bridgeKey);
            return sb.toString();
        }

        public List<String> coreArgs() {
            List<String> a = new ArrayList<>();
            if (h3 != null) { a.add("-h3"); a.add(h3.optString("ep")); a.add("-h3sni"); a.add(h3.optString("sni")); }
            if (h2 != null) { a.add("-h2"); a.add(h2.optString("ep")); a.add("-h2sni"); a.add(h2.optString("sni")); }
            if (bridgeUrl != null) { a.add("-bridge"); a.add(bridgeUrl); }
            if (bridgeUrl != null && !standby.isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (String u : standby) { if (sb.length() > 0) sb.append(','); sb.append(u); }
                a.add("-bridges"); a.add(sb.toString());
            }
            return a;
        }
    }

    // ------------------------------------------------------------ scan state (read by UI)
    public static volatile boolean scanning;
    public static volatile String scanStatus = "";
    private static volatile Process scanProc;
    private static final Object SCAN_LOCK = new Object();

    public static long lastScan(Context c) {
        return Core.prefs(c).getLong("lastScan", 0);
    }

    public static boolean isStale(Context c) {
        return Core.endpoints(c).isEmpty() || System.currentTimeMillis() - lastScan(c) > RESCAN_AGE_MS;
    }

    /** Starts a background scan when the list is empty or older than 6 h. */
    public static void maybeAutoScan(Context c, String why) {
        if (!Core.hasConfig(c) || scanning) return;
        if (skipDirectScans(c)) return;
        // after a scan that found nothing, wait 15 min before an automatic retry
        long lastTry = Core.prefs(c).getLong("lastScanTry", 0);
        if (isStale(c) && System.currentTimeMillis() - lastTry > 15L * 60 * 1000) {
            Core.log(L.t("اسکن خودکار: ") + why);
            startScan(c);
        }
    }

    private static volatile boolean stopReq;

    /**
     * v1.4: no automatic direct-MASQUE scans in Config + Psiphon mode (v1.8.2; it does not use WARP), nor in bridge
     * mode once the last direct real tests all failed (they only waste time/data on a network that blocks the direct
     * path). Manual "scan" still works.
     */
    public static boolean skipDirectScans(Context c) {
        String m = Core.mode(c);
        if (Core.MODE_CHAIN.equals(m)) return true;
        return Core.MODE_BRIDGE.equals(m) && Core.prefs(c).getLong("directFailAt", 0) > 0;
    }

    public static void stopScan() {
        stopReq = true;
        Process p = scanProc;
        if (p != null) p.destroy();
    }

    /** Starts a full scan in a background thread (no-op if one is running). */
    public static void startScan(Context ctx) {
        final Context c = ctx.getApplicationContext();
        synchronized (SCAN_LOCK) {
            if (scanning) return;
            scanning = true;
            stopReq = false;
        }
        new Thread(() -> {
            try {
                runScan(c);
            } finally {
                scanning = false;
                scanProc = null;
            }
        }, "o76-scan").start();
    }

    private static void runScan(Context c) {
        Core.prefs(c).edit().putLong("lastScanTry", System.currentTimeMillis()).apply();
        final List<String> snis = Core.snis(c);
        final boolean h2only = Core.h2Only(c);
        final List<JSONObject> found = Collections.synchronizedList(new ArrayList<>());
        final int[] total = {0};
        scanStatus = L.t("اسکن ") + (h2only ? "HTTP/2" : "HTTP/3 + HTTP/2") + L.t(" با ") + snis.size() + " SNI …";
        StringBuilder sl = new StringBuilder();
        for (String s : snis) { if (sl.length() > 0) sl.append(','); sl.append(s); }
        boolean stopped = false;
        try {
            List<String> args = new ArrayList<>();
            args.add("scan");
            args.add("-c"); args.add(Core.hasConfig(c) ? Core.cfg(c).getAbsolutePath() : "/nonexistent");
            args.add("-snis"); args.add(sl.toString());
            args.add("-proto"); args.add(h2only ? "h2" : "auto");
            args.add("-n"); args.add("96");
            args.add("-ports"); args.add(Core.ports(c));
            args.add("-h3ports"); args.add(Core.ports(c));
            args.add("-rotate=true");
            args.addAll(Core.dpiArgs(c));
            Process p = Core.start(c, args.toArray(new String[0]));
            scanProc = p;
            Core.pump(p, line -> {
                if (line.startsWith("TOTAL ")) {
                    try { total[0] = Integer.parseInt(line.substring(6).trim()); } catch (Exception ignored) { }
                } else if (line.startsWith("PROG ")) {
                    scanStatus = L.t("اسکن: ") + line.substring(5).trim() + L.t(" از ") + total[0] + L.t(" — سالم: ") + found.size();
                } else if (line.startsWith("RES ")) {
                    JSONObject o = parseRes(line);
                    if (o != null) found.add(o);
                } else if (line.startsWith("ERR")) {
                    Core.log(line);
                }
            });
            stopped = stopReq;
        } catch (Exception e) {
            Core.log("scan: " + e);
        }
        List<JSONObject> l;
        synchronized (found) { l = new ArrayList<>(found); }
        if (l.isEmpty()) {
            scanStatus = L.t("اسکن تمام شد: هیچ سرور سالمی پیدا نشد (فهرست قبلی حفظ شد). SNI دیگری در تنظیمات اضافه کنید.");
            Core.log("scan: nothing found");
            return;
        }
        Core.sort(l);
        // keep the old real-test results for entries that were found again
        List<JSONObject> old = Core.endpoints(c);
        for (JSONObject o : l) {
            for (JSONObject x : old) {
                if (Core.key(x).equals(Core.key(o)) && x.optInt("rok", -1) == 1 && System.currentTimeMillis() - x.optLong("rt", 0) < RESCAN_AGE_MS) {
                    try { o.put("rok", x.optInt("rok")).put("rms", x.optLong("rms")).put("kbps", x.optLong("kbps")).put("rt", x.optLong("rt")); }
                    catch (Exception ignored) { }
                }
            }
        }
        List<JSONObject> keep = new ArrayList<>();
        int n2 = 0, n3 = 0;
        for (JSONObject o : l) {
            if ("h3".equals(o.optString("proto"))) { if (n3++ < KEEP_H3) keep.add(o); }
            else if (n2++ < KEEP_H2) keep.add(o);
        }
        Core.saveEndpoints(c, keep);
        Core.prefs(c).edit().putLong("lastScan", System.currentTimeMillis()).apply();
        Core.log("scan found " + l.size() + " (h3 " + n3 + ", h2 " + n2 + ")" + (stopped ? " (stopped)" : ""));
        if (stopped || stopReq) {
            scanStatus = L.t("اسکن متوقف شد: ") + l.size() + L.t(" سرور با هندشیک سالم");
            return;
        }
        // a TLS handshake only proves the first packets pass; DPI may still stall the data afterwards.
        // Real test (trace + download through the tunnel) on a diverse set: different SNIs and ports.
        List<JSONObject> cand = pickDiverse(keep, REAL_SCAN_N);
        scanStatus = L.t("تست واقعی (عبور داده از تونل) روی ") + cand.size() + L.t(" ترکیب سرور/SNI/پورت …");
        List<JSONObject> res = realTest(c, cand, 250000, 15, true);
        int okN = 0;
        JSONObject best = null;
        for (JSONObject o : res) if (o.optInt("rok") == 1) { okN++; if (best == null || Core.realScore(o) < Core.realScore(best)) best = o; }
        if (best != null) {
            scanStatus = String.format(Locale.US, L.t("اسکن تمام شد: %d سرور سالم (HTTP/3: %d، HTTP/2: %d)؛ تست واقعی: %d از %d موفق — بهترین: %s [%s] تاخیر واقعی %dms، %d KB/s"),
                    l.size(), n3, n2, okN, res.size(), best.optString("ep"), best.optString("sni"), best.optLong("rms"), best.optLong("kbps"));
        } else {
            scanStatus = String.format(Locale.US, L.t("اسکن: %d سرور هندشیک سالم، اما در تست واقعی هیچ‌کدام داده رد نکرد (احتمال اختلال DPI). ")
                    + L.t("«خروجی گزارش» را بفرستید یا در تنظیمات، تنظیمات دستی را امتحان کنید."), l.size());
        }
        Core.log("real test: " + okN + "/" + res.size() + " passed");
    }

    static final int REAL_SCAN_N = 12;

    /**
     * Picks up to n HTTP/2 entries (handshake-healthy, not cooling down), spreading over SNIs and ports:
     * best per SNI first, then best per port not yet covered, then fill by latency. Entries that already
     * passed the real test come first.
     */
    public static List<JSONObject> pickDiverse(List<JSONObject> l, int n) {
        List<JSONObject> src = new ArrayList<>();
        for (JSONObject o : l) {
            if (!"h2".equals(o.optString("proto")) || coolingDown(o)) continue;
            if (o.optInt("ok", -1) == 0 || o.optInt("rok", -1) == 0) continue;
            src.add(o);
        }
        Core.sort(src);
        List<JSONObject> r = new ArrayList<>();
        java.util.Set<String> snis = new java.util.HashSet<>(), ports = new java.util.HashSet<>(), keys = new java.util.HashSet<>();
        for (JSONObject o : src) {
            if (r.size() >= n) break;
            if (o.optInt("rok", -1) == 1 && r.size() < n / 3) { r.add(o); keys.add(Core.key(o)); snis.add(o.optString("sni")); ports.add(port(o)); }
        }
        for (JSONObject o : src) {
            if (r.size() >= n) break;
            if (keys.contains(Core.key(o)) || snis.contains(o.optString("sni"))) continue;
            r.add(o); keys.add(Core.key(o)); snis.add(o.optString("sni")); ports.add(port(o));
        }
        for (JSONObject o : src) {
            if (r.size() >= n) break;
            if (keys.contains(Core.key(o)) || ports.contains(port(o))) continue;
            r.add(o); keys.add(Core.key(o)); ports.add(port(o));
        }
        for (JSONObject o : src) {
            if (r.size() >= n) break;
            if (keys.add(Core.key(o))) r.add(o);
        }
        return r;
    }

    private static String port(JSONObject o) {
        String ep = o.optString("ep");
        int i = ep.lastIndexOf(':');
        return i >= 0 ? ep.substring(i + 1) : ep;
    }

    /**
     * Real end-to-end test of the given entries (tunnel + cdn-cgi/trace warp=on + RTT + download), 4 in parallel.
     * Merges results (rok / rms / kbps) into the saved list and returns them.
     */
    public static List<JSONObject> realTest(Context c, List<JSONObject> eps, int dlBytes, int timeoutSec, boolean statusUpdates) {
        final List<JSONObject> res = Collections.synchronizedList(new ArrayList<>());
        if (eps.isEmpty() || !Core.hasConfig(c)) return res;
        StringBuilder sb = new StringBuilder();
        for (JSONObject o : eps) {
            if (sb.length() > 0) sb.append(';');
            sb.append(Core.key(o));
        }
        final int total = eps.size();
        try {
            List<String> args = new ArrayList<>();
            args.add("realtest"); args.add("-c"); args.add(Core.cfg(c).getAbsolutePath());
            args.add("-eps"); args.add(sb.toString());
            args.add("-t"); args.add(timeoutSec + "s");
            args.add("-dl"); args.add(String.valueOf(dlBytes));
            args.add("-n"); args.add("4");
            args.addAll(Core.dpiArgs(c));
            Process p = Core.start(c, args.toArray(new String[0]));
            if (statusUpdates) scanProc = p;
            Core.pump(p, line -> {
                String[] s = line.split(" ");
                if (line.startsWith("REAL ") && s.length >= 7) {
                    JSONObject o = Core.entry(s[1], s[2], s[3], 0, 1);
                    try {
                        o.remove("ms");
                        o.put("rok", 1).put("rms", Long.parseLong(s[4])).put("kbps", Long.parseLong(s[5])).put("rt", System.currentTimeMillis());
                    } catch (Exception ignored) { }
                    res.add(o);
                    Core.log(L.t("✓ واقعی ") + s[2] + " [" + s[3] + L.t("] تاخیر ") + s[4] + L.t("ms، ") + s[5] + " KB/s");
                } else if (line.startsWith("RFAIL ") && s.length >= 5) {
                    JSONObject o = Core.entry(s[1], s[2], s[3], 0, 1);
                    try {
                        o.remove("ms");
                        o.put("rok", 0).put("rt", System.currentTimeMillis());
                    } catch (Exception ignored) { }
                    res.add(o);
                    Core.log(L.t("✗ واقعی ") + s[2] + " [" + s[3] + L.t("] مرحله ") + s[4] + ": " + line.substring(Math.min(line.length(), line.indexOf(s[4]) + s[4].length())).trim());
                } else if (line.startsWith("ERR")) {
                    Core.log(line);
                }
                if (statusUpdates && (line.startsWith("REAL ") || line.startsWith("RFAIL "))) {
                    int ok = 0;
                    synchronized (res) { for (JSONObject o : res) if (o.optInt("rok") == 1) ok++; }
                    scanStatus = L.t("تست واقعی: ") + res.size() + L.t(" از ") + total + L.t(" — موفق: ") + ok;
                }
            });
        } catch (Exception e) {
            Core.log("realtest: " + e);
        }
        List<JSONObject> l;
        synchronized (res) { l = new ArrayList<>(res); }
        if (!l.isEmpty()) Core.mergeResults(c, l);
        if (l.size() >= 2) {
            int okN = 0;
            for (JSONObject o : l) if (o.optInt("rok") == 1) okN++;
            // v1.3: all direct real tests failed -> the UI suggests the bridge
            Core.prefs(c).edit().putLong("directFailAt", okN == 0 ? System.currentTimeMillis() : 0).apply();
        }
        return l;
    }

    /** "RES h3 ip:port ms sni" -> entry */
    static JSONObject parseRes(String line) {
        String[] s = line.split(" ");
        if (s.length < 5) return null;
        try {
            return Core.entry(s[1], s[2], s[4], Long.parseLong(s[3]), 1);
        } catch (Exception e) {
            return null;
        }
    }

    // ------------------------------------------------------------ quick probe
    /** Re-probes the given entries in parallel (TLS/QUIC handshake, 1.5 s), merges results, returns updated list. */
    public static List<JSONObject> probe(Context c, List<JSONObject> eps) {
        if (eps.isEmpty()) return Core.endpoints(c);
        StringBuilder sb = new StringBuilder();
        for (JSONObject o : eps) {
            if (sb.length() > 0) sb.append(';');
            sb.append(Core.key(o));
        }
        final List<JSONObject> res = new ArrayList<>();
        try {
            List<String> args = new ArrayList<>();
            args.add("probe"); args.add("-c"); args.add(Core.cfg(c).getAbsolutePath());
            args.add("-eps"); args.add(sb.toString()); args.add("-t"); args.add("2500ms");
            args.addAll(Core.dpiArgs(c));
            Process p = Core.start(c, args.toArray(new String[0]));
            Core.pump(p, line -> {
                if (line.startsWith("RES ")) {
                    JSONObject o = parseRes(line);
                    if (o != null) res.add(o);
                } else if (line.startsWith("FAIL ")) {
                    String[] s = line.split(" ");
                    if (s.length >= 4) {
                        JSONObject o = Core.entry(s[1], s[2], s[3], 0, 0);
                        o.remove("ft"); // a failed handshake probe is not a tunnel failure; keep it out of cooldown
                        res.add(o);
                    }
                }
            });
        } catch (Exception e) {
            Core.log("probe: " + e);
        }
        if (!res.isEmpty()) Core.mergeResults(c, res);
        return Core.endpoints(c);
    }

    private static boolean coolingDown(JSONObject o) {
        long ft = o.optLong("ft", 0);
        return ft > 0 && System.currentTimeMillis() - ft < FAIL_COOLDOWN_MS;
    }

    private static boolean skipH3(Context c) {
        if (Core.h2Only(c)) return true;
        long f = Core.prefs(c).getLong("h3FailAt", 0);
        return f > 0 && System.currentTimeMillis() - f < H3_SKIP_MS;
    }

    /** Candidates of one protocol: healthy/unknown first (sorted), excluding ones cooling down after a failure. */
    private static List<JSONObject> candidates(List<JSONObject> l, String proto, int max) {
        List<JSONObject> r = new ArrayList<>();
        for (JSONObject o : l) {
            if (!proto.equals(o.optString("proto"))) continue;
            if (coolingDown(o)) continue;
            r.add(o);
            if (r.size() >= max) break;
        }
        return r;
    }

    private static JSONObject bestOk(List<JSONObject> l, String proto) {
        for (JSONObject o : l) {
            if (proto.equals(o.optString("proto")) && o.optInt("ok", -1) == 1 && !coolingDown(o)) return o;
        }
        return null;
    }

    /**
     * Builds the connection plan. Pinned server is used as-is. Otherwise re-probes the top few
     * HTTP/3 and HTTP/2 servers and picks the lowest-latency healthy one of each. Blocking (≈1.5 s).
     */
    public static Plan plan(Context c) {
        Plan p = new Plan();
        boolean noH3 = skipH3(c);
        String pin = Core.pinned(c);
        List<JSONObject> l = Core.endpoints(c);
        if (!pin.isEmpty()) {
            JSONObject e = null;
            for (JSONObject o : l) if (Core.key(o).equals(pin)) e = o;
            if (e == null) e = Core.fromKey(pin);
            if (e != null) {
                p.pinned = true;
                if ("h3".equals(e.optString("proto"))) {
                    if (!Core.h2Only(c)) p.h3 = e;
                    JSONObject h2 = bestOk(l, "h2");
                    p.h2 = h2 != null ? h2 : Core.entry("h2", Core.DEFAULT_EP, e.optString("sni"), 0, -1);
                } else {
                    p.h2 = e;
                }
                return p;
            }
        }
        // HTTP/2: only servers whose real data test passed recently are trusted; when there are none,
        // run a quick real test (trace + 100 KB) on a diverse set before connecting.
        JSONObject realBest = bestReal(l);
        if (realBest == null && Core.hasConfig(c)) {
            List<JSONObject> cand = pickDiverse(l, 6);
            if (!cand.isEmpty()) {
                planStatus = L.t("تست واقعی ") + cand.size() + L.t(" سرور قبل از اتصال …");
                Core.log(planStatus);
                realTest(c, cand, 100000, 12, false);
                l = Core.endpoints(c);
                realBest = bestReal(l);
            }
        }
        if (!noH3) {
            List<JSONObject> cand = candidates(l, "h3", 3);
            if (Core.hasConfig(c) && !cand.isEmpty()) l = probe(c, cand);
            p.h3 = bestOk(l, "h3");
        }
        p.h2 = realBest != null ? realBest : bestOk(l, "h2");
        if (realBest == null && p.h2 != null) Core.log(L.t("هیچ سروری تست واقعی را رد نکرد؛ اتصال به بهترین هندشیک"));
        String sni = Core.firstSni(c);
        if (p.h2 == null) {
            List<JSONObject> any = candidates(l, "h2", 1);
            p.h2 = any.isEmpty() ? Core.entry("h2", Core.DEFAULT_EP, sni, 0, -1) : any.get(0);
        }
        if (p.h3 == null && !noH3 && l.isEmpty()) p.h3 = Core.entry("h3", Core.DEFAULT_EP_H3, sni, 0, -1);
        return p;
    }

    public static volatile String planStatus = "";

    /**
     * v1.3 bridge plan: best tested bridge (or the pinned one) + the MASQUE endpoint/SNI it passed with, HTTP/2 only.
     * When no bridge passed yet, tests the list first (blocking, up to ~2 min). Returns null when none works.
     */
    public static Plan bridgePlan(Context c) {
        JSONObject b = Bridges.best(c);
        if (b == null) {
            if (Bridges.busy) {
                long end = System.currentTimeMillis() + 180000;
                while (Bridges.busy && System.currentTimeMillis() < end) {
                    try { Thread.sleep(500); } catch (InterruptedException e) { return null; }
                }
                b = Bridges.best(c);
            }
            if (b == null) {
                if (Bridges.userList(c).isEmpty() && Bridges.poolSize(c) == 0) Bridges.fetch(c);
                planStatus = L.t("تست پل‌ها (پروکسی) قبل از اتصال …");
                Core.log(planStatus);
                Bridges.busy = true;
                try { Bridges.test(c, 400); } finally { Bridges.busy = false; }
                b = Bridges.best(c);
            }
        }
        if (b == null) return null;
        Plan p = new Plan();
        p.bridge = b;
        p.bridgeKey = b.optString("k");
        p.bridgeUrl = b.optString("u", p.bridgeKey);
        p.pinned = Bridges.addrOf(Bridges.pinned(c)).equals(Bridges.addrOf(p.bridgeKey)) && !Bridges.pinned(c).isEmpty();
        String ep = b.optString("ep", Core.DEFAULT_EP), sni = b.optString("sni", Core.firstSni(c));
        if ("w".equals(b.optString("kind"))) { ep = Core.DEFAULT_EP; sni = Core.firstSni(c); } // tested by v1.5-v1.8.1 (Worker kind)
        if (ep.isEmpty()) ep = Core.DEFAULT_EP;
        if (sni.isEmpty()) sni = Core.firstSni(c);
        p.h2 = Core.entry("h2", ep, sni, 0, -1);
        // v1.4: 2-3 other tested bridges stay warm in the core for instant failover (never when pinned)
        if (!p.pinned) p.standby = Bridges.warmSet(c, p.bridgeKey, 3);
        return p;
    }

    /** Best HTTP/2 entry with a passed real test within the last 6 h, not cooling down. */
    private static JSONObject bestReal(List<JSONObject> l) {
        JSONObject best = null;
        for (JSONObject o : l) {
            if (!"h2".equals(o.optString("proto")) || coolingDown(o)) continue;
            if (o.optInt("rok", -1) != 1 || o.optInt("ok", -1) == 0) continue;
            if (System.currentTimeMillis() - o.optLong("rt", 0) > RESCAN_AGE_MS) continue;
            if (best == null || Core.realScore(o) < Core.realScore(best)) best = o;
        }
        return best;
    }

    /** Marks an entry as failed (tunnel did not work) and re-sorts. */
    public static void markFailed(Context c, JSONObject e) {
        if (e == null) return;
        JSONObject f = Core.entry(e.optString("proto"), e.optString("ep"), e.optString("sni"), 0, 0);
        try { f.put("rok", 0); } catch (Exception ignored) { }
        List<JSONObject> one = new ArrayList<>();
        one.add(f);
        Core.mergeResults(c, one);
    }

    public static void markOk(Context c, String proto, String ep, String sni) {
        List<JSONObject> l = Core.endpoints(c);
        for (JSONObject o : l) {
            if (proto.equals(o.optString("proto")) && ep.equals(o.optString("ep")) && sni.equals(o.optString("sni"))) {
                List<JSONObject> one = new ArrayList<>();
                one.add(Core.entry(proto, ep, sni, o.optLong("ms", 0), 1));
                Core.mergeResults(c, one);
                return;
            }
        }
    }

    /** Blocks until a running scan ends (max ms). */
    public static void awaitScan(long maxMs) {
        long end = System.currentTimeMillis() + maxMs;
        while (scanning && System.currentTimeMillis() < end) {
            try { Thread.sleep(300); } catch (InterruptedException e) { return; }
        }
    }

    private Servers() {}
}
