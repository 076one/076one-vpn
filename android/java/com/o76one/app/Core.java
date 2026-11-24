package com.o76one.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Helpers: run the Go core binary, keep the log, store endpoints and settings. */
public final class Core {
    public static final String DEFAULT_SNI = "consumer-masque.cloudflareclient.com";
    public static final String DEFAULT_EP = "162.159.198.2:443";      // HTTP/2 default
    public static final String DEFAULT_EP_H3 = "162.159.198.1:443";   // HTTP/3 (QUIC) default

    public interface LineCallback { void onLine(String line); }
    /** v1.8.2: java.util.function is API 24+; these keep the app working on Android 5-6 (minSdk 21) */
    public interface Cancel { boolean getAsBoolean(); }
    public interface Fn<T> { void accept(T t); }

    // ---------------- log ----------------
    /** v1.5: every log line goes through O76App (persistent files/o76.log + in-memory ring). */
    public static void log(String s) {
        O76App.log(s);
    }

    /** newest first, last 80 lines (main screen) */
    public static String logText() {
        // read from the persistent log so lines from before a process restart are shown too
        List<String> l = new ArrayList<>(Arrays.asList(O76App.tail(80).split("\n")));
        Collections.reverse(l);
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (String s : l) { if (s.isEmpty()) continue; if (n++ >= 80) break; sb.append(s).append('\n'); }
        return sb.toString();
    }

    /** Removes anything that could be a secret (keys, tokens, long base64) and the WARP account identifiers. */
    static String scrub(String s, Context c) {
        s = s.replaceAll("[A-Za-z0-9+/=_-]{40,}", "<redacted>");
        // proxy credentials (scheme://user:pass@host) never leave the phone
        s = s.replaceAll("(socks5|socks4|http|https|auto)://[^@\\s/]+@", "$1://<auth>@");
        // v1.8.2: the user's own proxy links (Config + Psiphon mode) never leave the phone
        s = s.replaceAll("(?i)(vless|vmess|trojan|ss)://\\S+", "$1://<link>");
        s = s.replaceAll("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>");
        JSONObject cfg = readConfig(c);
        if (cfg != null) {
            for (String k : new String[]{"ipv6", "id", "access_token", "private_key"}) {
                String v = cfg.optString(k, "");
                if (v.length() > 3) s = s.replace(v, "<" + k + ">");
            }
        }
        return s;
    }

    /** Diagnostic report for sharing (no keys, tokens or account id). */
    public static String diagnostics(Context c) {
        StringBuilder sb = new StringBuilder();
        sb.append("076one diagnostic log\n");
        try {
            android.content.pm.PackageInfo pi = c.getPackageManager().getPackageInfo(c.getPackageName(), 0);
            sb.append("app: ").append(pi.versionName).append(" (").append(pi.versionCode).append(")\n");
        } catch (Exception ignored) { }
        sb.append("time: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.US).format(new Date())).append('\n');
        sb.append("android: ").append(android.os.Build.VERSION.RELEASE).append(" sdk ").append(android.os.Build.VERSION.SDK_INT)
                .append(" ").append(android.os.Build.MANUFACTURER).append(' ').append(android.os.Build.MODEL)
                .append(" abi ").append(android.os.Build.SUPPORTED_ABIS[0]).append('\n');
        try {
            ConnectivityManager cm = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
            android.net.NetworkInfo ni = cm.getActiveNetworkInfo();
            sb.append("network: ").append(ni == null ? "none" : ni.getTypeName() + "/" + ni.getSubtypeName()).append('\n');
            android.telephony.TelephonyManager tm = (android.telephony.TelephonyManager) c.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) sb.append("operator: ").append(tm.getNetworkOperatorName()).append(" (").append(tm.getNetworkOperator()).append(")\n");
        } catch (Exception ignored) { }
        sb.append("mode: ").append(mode(c)).append('\n');
        sb.append("settings: ").append(bestMode(c) ? "best (default) " : "custom ").append(dpiArgs(c)).append(" h2only=").append(h2Only(c))
                .append(" ports=").append(ports(c)).append('\n');
        sb.append("snis: ").append(snis(c)).append('\n');
        sb.append(Bridges.diag(c));
        sb.append(Chain.diag(c));
        sb.append(Aether.diag(c));
        sb.append(Fox.diag(c));
        sb.append(WarpPlus.diag(c));
        sb.append("pinned: ").append(pinned(c).isEmpty() ? "-" : pinned(c)).append('\n');
        sb.append("vpn: state=").append(O76VpnService.state).append(" ").append(O76VpnService.stateMsg)
                .append(" ").append(O76VpnService.proto).append(' ').append(O76VpnService.endpoint).append(' ').append(O76VpnService.sniUsed)
                .append(" realRtt=").append(O76VpnService.realRtt).append("ms rx=").append(O76VpnService.rxTotal)
                .append(" tx=").append(O76VpnService.txTotal).append(" switches=").append(O76VpnService.switches)
                .append(" bridge=").append(O76VpnService.bridgeInUse.isEmpty() ? "-" : O76VpnService.bridgeInUse)
                .append(" ttlDrops=").append(O76VpnService.ttlDrops).append('\n');
        long ls = Core.prefs(c).getLong("lastScan", 0);
        sb.append("lastScan: ").append(ls == 0 ? "never" : ((System.currentTimeMillis() - ls) / 60000) + " min ago").append('\n');
        sb.append("\nservers (proto ep sni hs-ms ok | real-rtt kbps rok):\n");
        int n = 0;
        for (JSONObject o : endpoints(c)) {
            if (n++ >= 25) break;
            sb.append(o.optString("proto")).append(' ').append(o.optString("ep")).append(' ').append(o.optString("sni"))
                    .append(' ').append(o.optLong("ms")).append(' ').append(o.optInt("ok", -1))
                    .append(" | ").append(o.optLong("rms", 0)).append(' ').append(o.optLong("kbps", 0)).append(' ').append(o.optInt("rok", -1)).append('\n');
        }
        sb.append("\nlog (oldest first, persistent, last 1500 lines):\n");
        sb.append(O76App.tail(1500));
        return scrub(sb.toString(), c);
    }

    // ---------------- files ----------------
    public static File bin(Context c) {
        return new File(c.getApplicationInfo().nativeLibraryDir, "libo76core.so");
    }

    public static File cfg(Context c) {
        return new File(c.getFilesDir(), "config.json");
    }

    public static boolean hasConfig(Context c) {
        return cfg(c).length() > 10;
    }

    public static JSONObject readConfig(Context c) {
        try (FileInputStream in = new FileInputStream(cfg(c))) {
            byte[] b = new byte[(int) cfg(c).length()];
            int n = 0;
            while (n < b.length) { int r = in.read(b, n, b.length - n); if (r < 0) break; n += r; }
            return new JSONObject(new String(b, 0, n, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return null;
        }
    }

    /** Validates and saves a usque-format config.json. Returns null on success or an error text. */
    public static String importConfig(Context c, String json) {
        try {
            JSONObject o = new JSONObject(json.trim());
            for (String k : new String[]{"private_key", "endpoint_pub_key", "ipv4"}) {
                if (o.optString(k, "").isEmpty()) return L.t("فیلد ") + k + L.t(" در کانفیگ نیست");
            }
            try (FileOutputStream out = new FileOutputStream(cfg(c))) {
                out.write(o.toString(2).getBytes(StandardCharsets.UTF_8));
            }
            return null;
        } catch (Exception e) {
            return L.t("JSON نامعتبر: ") + e.getMessage();
        }
    }

    // ---------------- process ----------------
    public static String systemDns(Context c) {
        try {
            ConnectivityManager cm = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network n = null;
            if (android.os.Build.VERSION.SDK_INT >= 23) n = cm.getActiveNetwork();
            else {
                // API 21-22: no getActiveNetwork(); take the connected network of the active type
                android.net.NetworkInfo act = cm.getActiveNetworkInfo();
                Network[] all = cm.getAllNetworks();
                if (act != null && all != null) for (Network x : all) {
                    android.net.NetworkInfo ni = cm.getNetworkInfo(x);
                    if (ni != null && ni.isConnected() && ni.getType() == act.getType()) { n = x; break; }
                }
            }
            if (n == null) return "";
            LinkProperties lp = cm.getLinkProperties(n);
            if (lp == null) return "";
            StringBuilder sb = new StringBuilder();
            for (InetAddress a : lp.getDnsServers()) {
                if (sb.length() > 0) sb.append(',');
                sb.append(a.getHostAddress());
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    public static Process start(Context c, String... args) throws Exception {
        return start(c, null, args);
    }

    /** start with extra environment variables (secrets such as the Cloudflare API token go here, never in argv) */
    public static Process start(Context c, Map<String, String> extraEnv, String... args) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(bin(c).getAbsolutePath());
        cmd.addAll(Arrays.asList(args));
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(c.getFilesDir());
        pb.redirectErrorStream(true);
        Map<String, String> env = pb.environment();
        env.put("O76_WATCH_STDIN", "1");
        env.put("O76_DNS", systemDns(c));
        if (extraEnv != null) env.putAll(extraEnv);
        return pb.start();
    }

    /** Reads output lines until the process ends; returns exit code. Blocking. */
    public static int pump(Process p, LineCallback cb) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                cb.onLine(line);
            }
        } catch (Exception ignored) {
        }
        try {
            return p.waitFor();
        } catch (InterruptedException e) {
            return -1;
        }
    }

    // ---------------- v1.4 connection mode ----------------
    public static final String MODE_WARP = "warp", MODE_BRIDGE = "bridge";
    /** v1.8.2: the user's own proxy link (Xray-core) with Psiphon on top; replaces the removed Worker mode */
    public static final String MODE_CHAIN = "chain";
    /** v1.6: Aether core (arm64 only; hidden when libaether.so is not installed) */
    public static final String MODE_AETHER = "aether";
    /** v1.7: Firefox account + Firefox/Mozilla VPN proxy network (libfpn.so, Predator VPN core) */
    public static final String MODE_FOX = "fox";
    /** v1.8: warp-plus (WARP / WARP-in-WARP / Psiphon over WARP) */
    public static final String MODE_WPLUS = "wplus";

    /** "warp" (direct MASQUE) | "bridge" (MASQUE through a public proxy) | "chain" | "aether" | "fox" | "wplus" */
    public static String mode(Context c) {
        String m = prefs(c).getString("mode", "");
        if (m.isEmpty()) m = prefs(c).getBoolean("bridgeOn", false) ? MODE_BRIDGE : MODE_WARP; // v1.3 migration
        if ("worker".equals(m)) {
            // v1.8.2: Worker mode was removed -> Config + Psiphon when a config is saved, else the default mode
            m = Chain.configured(c) ? MODE_CHAIN : MODE_WARP;
            prefs(c).edit().putString("mode", m).apply();
        }
        if (MODE_CHAIN.equals(m) && !Chain.available(c)) m = MODE_WARP;
        if (MODE_AETHER.equals(m) && !Aether.available(c)) m = MODE_WARP; // v1.6: no libaether.so on this ABI
        if (MODE_FOX.equals(m) && !Fox.available(c)) m = MODE_WARP;
        if (MODE_WPLUS.equals(m) && !WarpPlus.available(c)) m = MODE_WARP;
        return m;
    }

    public static void setMode(Context c, String m) {
        prefs(c).edit().putString("mode", m).putBoolean("bridgeOn", MODE_BRIDGE.equals(m)).apply();
    }

    public static String modeLabel(String m) {
        return MODE_BRIDGE.equals(m) ? L.t("پل پروکسی") : MODE_CHAIN.equals(m) ? L.t("کانفیگ + سایفون") : MODE_AETHER.equals(m) ? "Aether" : MODE_FOX.equals(m) ? "Firefox" : MODE_WPLUS.equals(m) ? L.t("وارپ+") : L.t("WARP مستقیم");
    }

    /** Cloudflare colos near Iran (slight preference) */
    private static final java.util.Set<String> NEAR = new java.util.HashSet<>(Arrays.asList(
            "FRA", "AMS", "IST", "VIE", "MUC", "DUS", "HAM", "BER", "WAW", "PRG", "BUD", "SOF", "OTP", "ATH", "SKG", "MXP",
            "ZRH", "CDG", "LHR", "ARN", "HEL", "CPH", "BEG", "TIA", "KBP", "DME", "LED", "DXB", "FJR", "BAH", "TBS", "EVN",
            "GYD", "KWI", "DOH", "MCT", "RUH", "JED", "AMM", "BEY", "LCA", "ADB", "ESB", "BSR", "BGW", "EBL", "ISU", "NJF", "ALA", "TAS"));

    public static long coloPenalty(String colo) {
        if (colo == null || colo.isEmpty() || colo.equals("-")) return 40;
        return NEAR.contains(colo.toUpperCase(Locale.US)) ? 0 : 80;
    }

    /** base score divided by a smoothed success rate: (sc+1)/(sc+fc+2) */
    public static long stabilityScore(long base, int sc, int fc) {
        double rate = (sc + 1.0) / (sc + fc + 2.0);
        return (long) (base / Math.max(0.15, rate));
    }

    // ---------------- prefs ----------------
    public static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("o76", Context.MODE_PRIVATE);
    }

    /**
     * v1.2 default SNI rotation. Cloudflare's MASQUE server accepts any SNI (authentication is the enrolled
     * client certificate and the pinned server key), so neutral / domestic names are mixed with the official
     * one: an SNI-based DPI rule for *.cloudflareclient.com does not hit the others. All verified with a full
     * tunnel + trace (warp=on) + download in testing (not from Iran).
     */
    public static final String[] DEFAULT_SNIS = {
            "www.speedtest.net",
            DEFAULT_SNI,
            "www.digikala.com",
            "www.aparat.com",
            "snapp.ir",
            "divar.ir",
            "cdn.jsdelivr.net",
            "www.cloudflare.com",
    };
    private static final String[] OLD_DEFAULT_SNIS = {
            DEFAULT_SNI, "zero-trust-client.cloudflareclient.com", "consumer-masque-proxy.cloudflareclient.com",
    };

    public static List<String> snis(Context c) {
        SharedPreferences p = prefs(c);
        String raw = p.getString("snis", null);
        if (raw != null && p.getInt("sniVer", 1) < 2) {
            // v1.2: switch to the new rotation list, keeping SNIs the user added themselves
            List<String> l = new ArrayList<>(Arrays.asList(DEFAULT_SNIS));
            for (String s : parseSnis(raw)) if (!l.contains(s) && !Arrays.asList(OLD_DEFAULT_SNIS).contains(s)) l.add(s);
            saveSnis(c, l);
            p.edit().putInt("sniVer", 2).apply();
            return l;
        }
        if (raw == null) {
            p.edit().putInt("sniVer", 2).apply();
            // first run of v1.1: migrate the single SNI of v1.0
            List<String> l = new ArrayList<>(Arrays.asList(DEFAULT_SNIS));
            String old = p.getString("sni", "").trim();
            if (!old.isEmpty() && !l.contains(old)) l.add(0, old);
            saveSnis(c, l);
            return l;
        }
        List<String> l = parseSnis(raw);
        if (l.isEmpty()) l.add(DEFAULT_SNI);
        return l;
    }

    public static List<String> parseSnis(String raw) {
        List<String> l = new ArrayList<>();
        for (String s : raw.split("[\\s,;]+")) {
            s = s.trim().toLowerCase(Locale.US);
            if (s.isEmpty() || l.contains(s)) continue;
            if (!s.matches("[a-z0-9.-]+")) continue;
            l.add(s);
        }
        return l;
    }

    public static void saveSnis(Context c, List<String> l) {
        StringBuilder sb = new StringBuilder();
        for (String s : l) { if (sb.length() > 0) sb.append('\n'); sb.append(s); }
        prefs(c).edit().putString("snis", sb.toString()).apply();
    }

    public static String firstSni(Context c) {
        return snis(c).get(0);
    }

    public static boolean h2Only(Context c) {
        return prefs(c).getBoolean("h2only", false);
    }

    // ---------------- anti-DPI settings ----------------
    /** "Best settings" (default): the stored custom values are ignored and the recommended ones are used. */
    public static boolean bestMode(Context c) { return prefs(c).getBoolean("best", true); }

    public static final String BEST_FRAG = "both", BEST_FRAGSIZE = "10-50", BEST_FRAGDELAY = "1-5", BEST_FP = "chrome";
    public static final int BEST_MTU = 1280, BEST_MSS = 1300;
    public static final String DEFAULT_PORTS = "443,500,1701,4443,4500,8095,8443";

    public static String frag(Context c) { return bestMode(c) ? BEST_FRAG : prefs(c).getString("frag", BEST_FRAG); }
    public static String fragSize(Context c) { return bestMode(c) ? BEST_FRAGSIZE : prefs(c).getString("fragsize", BEST_FRAGSIZE); }
    public static String fragDelay(Context c) { return bestMode(c) ? BEST_FRAGDELAY : prefs(c).getString("fragdelay", BEST_FRAGDELAY); }
    public static String fp(Context c) { return bestMode(c) ? BEST_FP : prefs(c).getString("fp", BEST_FP); }
    public static int mtu(Context c) { return bestMode(c) ? BEST_MTU : prefs(c).getInt("mtu", BEST_MTU); }
    public static int mss(Context c) { return bestMode(c) ? BEST_MSS : prefs(c).getInt("mss", BEST_MSS); }
    public static boolean noDelay(Context c) { return bestMode(c) || prefs(c).getBoolean("nodelay", true); }
    public static String ports(Context c) {
        String p = prefs(c).getString("ports", DEFAULT_PORTS).replaceAll("[^0-9,]", "");
        return p.isEmpty() ? DEFAULT_PORTS : p;
    }

    /** Core flags for the anti-DPI transport (scan, probe, test, realtest, vpn). */
    public static List<String> dpiArgs(Context c) {
        List<String> a = new ArrayList<>();
        a.add("-frag"); a.add(frag(c));
        a.add("-fragsize"); a.add(fragSize(c));
        a.add("-fragdelay"); a.add(fragDelay(c));
        a.add("-fp"); a.add(fp(c));
        a.add("-mtu"); a.add(String.valueOf(mtu(c)));
        a.add("-mss"); a.add(String.valueOf(mss(c)));
        a.add("-nodelay=" + noDelay(c));
        return a;
    }

    /** Pinned endpoint key ("proto|ip:port|sni") or "" for automatic selection. */
    public static String pinned(Context c) {
        return prefs(c).getString("pinned", "");
    }

    public static void setPinned(Context c, String key) {
        prefs(c).edit().putString("pinned", key == null ? "" : key).apply();
    }

    // ---------------- endpoints ----------------
    /** Entry: {proto:"h3"|"h2", ep:"ip:port", sni, ms, ok:1|0|-1 (healthy|failed|unknown), t:last check, ft:fail time} */
    public static String key(JSONObject o) {
        return o.optString("proto", "h2") + "|" + o.optString("ep") + "|" + o.optString("sni", DEFAULT_SNI);
    }

    public static JSONObject entry(String proto, String ep, String sni, long ms, int ok) {
        JSONObject o = new JSONObject();
        try {
            o.put("proto", proto).put("ep", ep).put("sni", sni).put("ms", ms).put("ok", ok).put("t", System.currentTimeMillis());
            if (ok == 0) o.put("ft", System.currentTimeMillis());
        } catch (Exception ignored) { }
        return o;
    }

    public static JSONObject fromKey(String key) {
        String[] p = key.split("\\|");
        if (p.length != 3) return null;
        return entry(p[0], p[1], p[2], 0, -1);
    }

    private static final Object EP_LOCK = new Object();
    private static volatile int epVersion;

    public static int epVersion() { return epVersion; }

    /** Endpoint list, always sorted (healthy by ping, then unknown, failed last). */
    public static List<JSONObject> endpoints(Context c) {
        synchronized (EP_LOCK) {
            List<JSONObject> l = new ArrayList<>();
            try {
                JSONArray a = new JSONArray(prefs(c).getString("eps2", "[]"));
                for (int i = 0; i < a.length(); i++) {
                    JSONObject o = a.optJSONObject(i);
                    if (o != null && !o.optString("ep").isEmpty()) l.add(o);
                }
            } catch (Exception ignored) { }
            sort(l);
            return l;
        }
    }

    /** 0 real data passed, 1 handshake ok (no real test yet), 2 unknown, 3 failed / real data failed */
    private static int rank(JSONObject o) {
        int ok = o.optInt("ok", -1), rok = o.optInt("rok", -1);
        if (ok == 0 || rok == 0) return 3;
        if (rok == 1) return 0;
        if (ok == 1) return 1;
        return 2;
    }

    public static void sort(List<JSONObject> l) {
        Collections.sort(l, (x, y) -> {
            int r = Integer.compare(rank(x), rank(y));
            if (r != 0) return r;
            if (rank(x) == 0) return Long.compare(realScore(x), realScore(y));
            long mx = x.optLong("ms", 0), my = y.optLong("ms", 0);
            if (mx <= 0) mx = Long.MAX_VALUE;
            if (my <= 0) my = Long.MAX_VALUE;
            return Long.compare(mx, my);
        });
    }

    /** real delay, with a penalty for slow throughput (<100 KB/s) */
    public static long realScore(JSONObject o) {
        long rms = o.optLong("rms", 0);
        if (rms <= 0) rms = 9999;
        long kb = o.optLong("kbps", 0);
        if (kb > 0 && kb < 100) rms += (100 - kb) * 5;
        return rms;
    }

    public static void saveEndpoints(Context c, List<JSONObject> l) {
        synchronized (EP_LOCK) {
            List<JSONObject> s = new ArrayList<>(l);
            sort(s);
            JSONArray a = new JSONArray();
            for (JSONObject o : s) a.put(o);
            prefs(c).edit().putString("eps2", a.toString()).apply();
            epVersion++;
        }
    }

    /** Merges results (same key -> updated) into the saved list and re-sorts. */
    public static void mergeResults(Context c, List<JSONObject> results) {
        synchronized (EP_LOCK) {
            List<JSONObject> l = endpoints(c);
            for (JSONObject r : results) {
                String k = key(r);
                boolean found = false;
                for (JSONObject o : l) {
                    if (key(o).equals(k)) {
                        try {
                            int ok = r.optInt("ok", -1);
                            o.put("ok", ok).put("t", System.currentTimeMillis());
                            if (r.optLong("ms", 0) > 0) o.put("ms", r.optLong("ms"));
                            if (ok == 0) o.put("ft", System.currentTimeMillis());
                            else if (ok == 1) o.remove("ft");
                            if (r.has("rok")) {
                                o.put("rok", r.optInt("rok")).put("rt", System.currentTimeMillis());
                                if (r.optInt("rok") == 1) o.put("rms", r.optLong("rms")).put("kbps", r.optLong("kbps"));
                                else o.put("ft", System.currentTimeMillis());
                            }
                        } catch (Exception ignored) { }
                        found = true;
                    }
                }
                if (!found) l.add(r);
            }
            saveEndpoints(c, l);
        }
    }

    public static void removeEndpoint(Context c, String key) {
        synchronized (EP_LOCK) {
            List<JSONObject> l = endpoints(c), n = new ArrayList<>();
            for (JSONObject o : l) if (!key(o).equals(key)) n.add(o);
            saveEndpoints(c, n);
        }
    }

    public static String protoLabel(String p) {
        return "h3".equals(p) ? "HTTP/3" : "ws".equals(p) ? "VLESS-WS" : "wg".equals(p) ? "WireGuard" : "gool".equals(p) ? "gool" : "HTTP/2";
    }

    public static String fmtSpeed(double bps) {
        if (bps < 1024) return String.format(Locale.US, "%.0f B/s", bps);
        if (bps < 1024 * 1024) return String.format(Locale.US, "%.1f KB/s", bps / 1024);
        return String.format(Locale.US, "%.2f MB/s", bps / 1024 / 1024);
    }

    public static String fmtBytes(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024 * 1024) return String.format(Locale.US, "%.1f KB", b / 1024.0);
        if (b < 1024L * 1024 * 1024) return String.format(Locale.US, "%.1f MB", b / 1024.0 / 1024);
        return String.format(Locale.US, "%.2f GB", b / 1024.0 / 1024 / 1024);
    }

    private Core() {}
}
