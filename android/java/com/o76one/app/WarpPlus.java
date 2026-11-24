package com.o76one.app;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * v1.8 "وارپ+" mode: WARP over WireGuard (UDP) with two extra layers, run by warp-plus (bepass-org, MIT) shipped as
 * lib/<abi>/libwplus.so and serving a local SOCKS5 port; o76core "svpn" carries the TUN into it.
 *   warp   : plain WARP (WireGuard)
 *   gool   : WARP inside WARP (two WARP identities, the second hop runs inside the first)
 *   psiphon: Psiphon (psiphon-tunnel-core, GPL-3.0) inside WARP, exit in the chosen country
 * The WARP identities live in files/wplus/{primary,secondary}. They are registered once; registration goes through the
 * best working bridge that reaches abroad (socks5/http) when one exists, because direct registration is blocked on
 * some Iranian networks. Two local patches to warp-plus: the bridge for registration (WP_REG_PROXY) and a working
 * connection test (the upstream test URL answers 404 now).
 */
public final class WarpPlus {
    private WarpPlus() { }

    public static final String VERSION = "f70ea7e (2025-11-17)";
    public static final String REPO = "https://github.com/bepass-org/warp-plus";
    public static final String V_WARP = "warp", V_GOOL = "gool", V_PSIPHON = "psiphon";
    public static final String[] COUNTRIES = {"DE", "NL", "GB", "FR", "US", "CA", "SE", "FI", "CH", "AT", "IT", "ES", "PL",
            "RO", "BE", "DK", "NO", "IE", "JP", "SG", "IN", "AU"};

    public static File bin(Context c) { return new File(c.getApplicationInfo().nativeLibraryDir, "libwplus.so"); }
    public static boolean available(Context c) { File f = bin(c); return f.isFile() && f.length() > 1_000_000; }

    public static File dir(Context c) {
        File d = new File(c.getFilesDir(), "wplus");
        if (!d.isDirectory()) //noinspection ResultOfMethodCallIgnored
            d.mkdirs();
        return d;
    }

    public static String variant(Context c) { return Core.prefs(c).getString("wpVariant", V_PSIPHON); }
    public static void setVariant(Context c, String v) { Core.prefs(c).edit().putString("wpVariant", v).apply(); }
    public static String country(Context c) { return Core.prefs(c).getString("wpCountry", "DE"); }
    public static void setCountry(Context c, String v) { Core.prefs(c).edit().putString("wpCountry", v).apply(); }
    /** custom WARP endpoint "ip:port" (empty = random from the WARP ranges, or scan) */
    public static String endpoint(Context c) { return Core.prefs(c).getString("wpEndpoint", ""); }
    public static void setEndpoint(Context c, String v) { Core.prefs(c).edit().putString("wpEndpoint", v == null ? "" : v.trim()).apply(); }
    public static boolean scan(Context c) { return Core.prefs(c).getBoolean("wpScan", true); }
    public static void setScan(Context c, boolean on) { Core.prefs(c).edit().putBoolean("wpScan", on).apply(); }
    public static boolean v4only(Context c) { return Core.prefs(c).getBoolean("wpV4", true); }
    public static void setV4only(Context c, boolean on) { Core.prefs(c).edit().putBoolean("wpV4", on).apply(); }

    public static boolean hasIdentity(Context c, String which) {
        return new File(new File(dir(c), which), "wgcf-identity.json").isFile();
    }

    /** forgets the WARP identities of this mode (a new one is registered on the next connect) */
    public static void resetIdentity(Context c) {
        for (String w : new String[]{"primary", "secondary"}) {
            File d = new File(dir(c), w);
            File[] fs = d.listFiles();
            if (fs != null) for (File f : fs) //noinspection ResultOfMethodCallIgnored
                f.delete();
            //noinspection ResultOfMethodCallIgnored
            d.delete();
        }
        Core.log(L.t("وارپ+: هویت‌های WARP این حالت پاک شد"));
    }

    public static String variantLabel(String v) {
        return V_GOOL.equals(v) ? L.t("وارپ در وارپ") : V_PSIPHON.equals(v) ? L.t("سایفون") : L.t("وارپ ساده");
    }

    public static String describe(Context c) {
        String v = variant(c);
        return variantLabel(v) + (V_PSIPHON.equals(v) ? " (" + country(c) + ")" : "")
                + (endpoint(c).isEmpty() ? (scan(c) ? L.t(" — اسکن endpoint") : L.t(" — endpoint تصادفی")) : " — " + endpoint(c));
    }

    public static String diag(Context c) {
        return "wplus: available=" + available(c) + " variant=" + variant(c) + " country=" + country(c) + " ep=" + endpoint(c)
                + " scan=" + scan(c) + " v4=" + v4only(c) + " id1=" + hasIdentity(c, "primary") + " id2=" + hasIdentity(c, "secondary") + "\n";
    }

    /** the bridge used for registering identities: best working one that reaches abroad, socks5/http only */
    static String regBridge(Context c) {
        StringBuilder sb = new StringBuilder(); int n = 0;
        for (org.json.JSONObject o : Bridges.results(c, "bridgeRes")) {
            if (o.optInt("ok", -1) != 1 || Bridges.coolingDown(o) || Bridges.intl(o) != 1) continue;
            String u = o.optString("u", o.optString("k"));
            if (u.startsWith("socks5://") || u.startsWith("socks5h://") || u.startsWith("http://")) {
                if (n > 0) sb.append(','); sb.append(u); if (++n >= 6) break; // v1.8.1: several bridges, then direct
            }
        }
        return n == 0 ? null : sb.toString();
    }

    // ---------------- tunnel ----------------
    private static final Pattern KV = Pattern.compile("(\\w[\\w./-]*)=(\"(?:[^\"\\\\]|\\\\.)*\"|\\S+)");

    public static final class Run {
        Process p;
        int port;
        String variant = "", label = "";
        volatile boolean up, dead;
        volatile String err = "", endpoint = "", exit = "";
        long startedAt = System.currentTimeMillis();
        volatile long lastLine = System.currentTimeMillis();

        void onLine(String l) {
            lastLine = System.currentTimeMillis();
            String level = "", msg = l;
            java.util.Map<String, String> kv = new java.util.HashMap<>();
            Matcher m = KV.matcher(l);
            while (m.find()) {
                String v = m.group(2);
                if (v.startsWith("\"")) v = v.substring(1, v.length() - 1).replace("\\\"", "\"");
                kv.put(m.group(1), v);
            }
            if (kv.containsKey("msg")) { msg = kv.get("msg"); level = kv.containsKey("level") ? kv.get("level") : ""; }
            if (msg.startsWith("{")) return; // psiphon JSON notices
            if ("serving proxy".equals(msg)) {
                up = true;
                return;
            }
            if ("using warp endpoints".equals(msg) && kv.containsKey("endpoints")) {
                endpoint = kv.get("endpoints").replace("[", "").replace("]", "").split(" ")[0];
                Core.log(L.t("وارپ+: endpoint ") + endpoint);
                return;
            }
            if ("connection test failed".equals(msg)) {
                err = L.t("تست اتصال داخل WARP ناموفق") + (kv.containsKey("error") ? " (" + kv.get("error") + ")" : "");
                return; // repeats many times; summarised on failure
            }
            if ("creating new identity".equals(msg)) { Core.log(L.t("وارپ+: ساخت هویت WARP تازه…")); return; }
            if (msg.contains("psiphon started successfully")) { Core.log(L.t("وارپ+: سایفون وصل شد")); return; }
            if (msg.startsWith("running in")) { Core.log(L.t("وارپ+: ") + msg); return; }
            if ("ERROR".equals(level) || "WARN".equals(level) || l.startsWith("error:") || l.startsWith("panic")) {
                err = msg + (kv.containsKey("error") ? ": " + kv.get("error") : "");
                Core.log(L.t("وارپ+: ") + err);
            }
        }
    }

    public static Run startTunnel(Context c, Core.Cancel cancelled) throws Exception {
        killStale(c);
        final Run r = new Run();
        r.port = Aether.freePort();
        r.variant = variant(c);
        List<String> a = new ArrayList<>();
        a.add("--bind"); a.add("127.0.0.1:" + r.port);
        a.add("--cache-dir"); a.add(dir(c).getAbsolutePath());
        a.add("--dns"); a.add("1.1.1.1");
        if (v4only(c)) a.add("-4");
        if (V_GOOL.equals(r.variant)) a.add("--gool");
        else if (V_PSIPHON.equals(r.variant)) { a.add("--cfon"); a.add("--country"); a.add(country(c)); }
        String ep = endpoint(c);
        if (!ep.isEmpty()) { a.add("-e"); a.add(ep); }
        else if (scan(c)) a.add("--scan");
        boolean needId = !hasIdentity(c, "primary") || (V_GOOL.equals(r.variant) && !hasIdentity(c, "secondary"));
        String reg = needId ? regBridge(c) : null;
        r.label = describe(c);
        Core.log(L.t("وارپ+ (warp-plus): شروع ") + r.label + " socks=127.0.0.1:" + r.port
                + (needId ? (reg == null ? L.t(" — ثبت هویت WARP مستقیم") : L.t(" — ثبت هویت WARP از طریق پل‌ها: ") + reg.split(",").length) : ""));

        List<String> cmd = new ArrayList<>();
        cmd.add(bin(c).getAbsolutePath());
        cmd.addAll(a);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir(c));
        pb.redirectErrorStream(true);
        Map<String, String> env = pb.environment();
        for (String k : new String[]{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"}) env.remove(k);
        env.put("HOME", dir(c).getAbsolutePath());
        if (reg != null) env.put("WP_REG_PROXY", reg); // env, not argv: may carry proxy credentials
        r.p = pb.start();
        try { r.p.getOutputStream().close(); } catch (Exception ignored) { }
        final Process p = r.p;
        new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) { line = line.trim(); if (!line.isEmpty()) r.onLine(line); }
            } catch (Exception ignored) { }
            int code = -1;
            try { code = p.waitFor(); } catch (InterruptedException ignored) { }
            r.dead = true;
            Core.log(L.t("وارپ+: پردازش پایان یافت (کد ") + code + ")");
        }, "o76-wplus-log").start();
        // psiphon needs time to find a server; the endpoint scan adds ~20 s
        long upMs = (V_PSIPHON.equals(r.variant) ? 180_000 : 100_000) + (ep.isEmpty() && scan(c) ? 40_000 : 0);
        while (!r.up) {
            if (cancelled.getAsBoolean()) { stop(r); throw new InterruptedException("cancelled"); }
            if (r.dead) throw new Exception(L.t("وارپ+ وصل نشد") + (r.err.isEmpty() ? "" : ": " + r.err) + hint(c, needId));
            if (System.currentTimeMillis() - r.startedAt > upMs) {
                stop(r);
                throw new Exception(L.t("وارپ+ در ") + upMs / 1000 + L.t(" ثانیه آماده نشد") + (r.err.isEmpty() ? "" : " (" + r.err + ")") + hint(c, needId));
            }
            Thread.sleep(250);
        }
        r.exit = V_PSIPHON.equals(r.variant) ? L.t("سایفون ") + country(c) : V_GOOL.equals(r.variant) ? L.t("WARP (دو لایه)") : "WARP";
        Core.log(L.t("وارپ+: آماده در ") + (System.currentTimeMillis() - r.startedAt) / 1000 + L.t(" ثانیه — ") + r.label);
        return r;
    }

    private static String hint(Context c, boolean neededId) {
        if (neededId && !hasIdentity(c, "primary"))
            return L.t(" — ثبت هویت WARP انجام نشد؛ در حالت «پل» یک پل سالم با دسترسی خارج پیدا کنید و دوباره وصل شوید");
        return L.t(" — UDP (WireGuard) روی این اینترنت احتمالاً بسته است؛ endpoint/پورت دیگری امتحان کنید");
    }

    public static void stop(Run r) {
        if (r == null || r.p == null) return;
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
        }, "o76-wplus-kill").start();
    }

    /** kills libwplus.so processes left from a previous app process */
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
                if (cl.split("\0")[0].equals(me)) android.os.Process.killProcess(Integer.parseInt(n));
            } catch (Exception ignored) { }
        }
    }
}
