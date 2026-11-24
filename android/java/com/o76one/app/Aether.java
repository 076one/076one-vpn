package com.o76one.app;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * v1.6 "Aether" mode: runs the Aether core (Aether v2.4.0 by CluvexStudio, AGPL-3.0, an unmodified static
 * arm64 musl build shipped as lib/arm64-v8a/libaether.so) as a separate process that opens a WARP tunnel and serves
 * it as a local SOCKS5 proxy; o76core "svpn" then carries the TUN into that SOCKS port.
 * Our existing WARP identity is converted (o76core aetherid) so no new device is registered.
 */
public final class Aether {
    private Aether() { }

    public static final String VERSION = "2.4.0";
    public static final String REPO = "https://github.com/CluvexStudio/Aether";
    public static final String P_H2 = "h2", P_H3 = "h3", P_WG = "wg", P_GOOL = "gool";
    public static final String CF_SNI = "www.cloudflare.com"; // Aether's own default
    /** v1.6.1: startup limits live in AetherWatch (idle 60 s only while nothing happens, hard cap 240 s) */
    public static final long HARD_MS = AetherWatch.HARD_MS;
    /** after being up: no re-validation for this long while reconnecting -> fail over (restart) */
    public static final long DOWN_MS = AetherWatch.REVALIDATE_MS;
    /** after being up and dropped: no progress line at all for this long (and not mid-handshake) -> restart early */
    public static final long DOWN_IDLE_MS = 30_000;

    // ---------------- availability / prefs ----------------
    public static File bin(Context c) {
        return new File(c.getApplicationInfo().nativeLibraryDir, "libaether.so");
    }

    /** Only the arm64-v8a APK lib dir carries libaether.so; the mode is hidden everywhere else. */
    public static boolean available(Context c) {
        File f = bin(c);
        return f.isFile() && f.length() > 1_000_000;
    }

    public static String proto(Context c) { return Core.prefs(c).getString("aProto", P_H2); }
    public static void setProto(Context c, String p) { Core.prefs(c).edit().putString("aProto", p).apply(); }

    /** SNI for the MASQUE handshakes; default = the first entry of the app's SNI list */
    public static String sni(Context c) {
        String s = Core.prefs(c).getString("aSni", "");
        return s.isEmpty() ? Core.firstSni(c) : s;
    }
    public static void setSni(Context c, String s) { Core.prefs(c).edit().putString("aSni", s).apply(); }

    public static boolean viaBridge(Context c) { return Core.prefs(c).getBoolean("aBridge", false); }
    public static void setViaBridge(Context c, boolean on) { Core.prefs(c).edit().putBoolean("aBridge", on).apply(); }

    /**
     * «خروجی غیر ایران» (--exit-loc !IR). v1.6.1: default OFF, and switched off once for everyone who had it on in v1.6:
     * Cloudflare gives WARP users in Iran an exit IP that geolocates as IR (traffic still leaves at a foreign colo,
     * unfiltered), so with this on Aether rejected every working tunnel.
     */
    public static boolean exitNotIR(Context c) {
        android.content.SharedPreferences sp = Core.prefs(c);
        if (!sp.getBoolean("aExitMig161", false)) {
            sp.edit().putBoolean("aExitNotIR", false).putBoolean("aExitMig161", true).apply();
            return false;
        }
        return sp.getBoolean("aExitNotIR", false);
    }
    public static void setExitNotIR(Context c, boolean on) {
        Core.prefs(c).edit().putBoolean("aExitNotIR", on).putBoolean("aExitMig161", true).apply();
    }

    /** Persian explanation shown under the switch and logged when it is turned off automatically */
    public static String exitIrNote() { return L.t("Cloudflare به کاربران WARP در ایران IP خروجی‌ای می‌دهد که «ایران (IR)» شناخته می‌شود، ")
            + L.t("ولی ترافیک از دیتاسنتر Cloudflare در خارج (مثلاً فرانکفورت) بیرون می‌رود و فیلتر نیست. با روشن بودن این گزینه Aether ")
            + L.t("همهٔ تونل‌های سالم را رد می‌کند؛ پس خاموش بماند. سایت‌هایی که کاربران ایران را مسدود می‌کنند همچنان ممکن است شما را ")
            + L.t("ایرانی ببینند — برای خروجی غیر ایران پروتکل gool (WireGuard داخل MASQUE) را امتحان کنید."); }

    /** two "exit location IR rejected" -> option off, explained in the log; the caller restarts without --exit-loc */
    static void disableExitLocAfterIR(Context c) {
        setExitNotIR(c, false);
        Core.log(L.t("Aether: تونل دو بار تأیید شد ولی چون خروجی «IR» بود رد شد ← «خروجی غیر ایران» خاموش شد و Aether بدون آن دوباره اجرا می‌شود."));
        Core.log("Aether: " + exitIrNote());
    }

    /** the bridge is used for HTTP/2 only (HTTP/3 needs UDP ASSOCIATE, WireGuard is UDP) */
    public static boolean bridgeApplies(Context c) {
        return viaBridge(c) && P_H2.equals(proto(c));
    }

    /** needs our WARP (MASQUE) account: every protocol but plain WireGuard */
    public static boolean needsWarpConfig(Context c) { return !P_WG.equals(proto(c)); }

    public static String protoLabel(String p) {
        return P_H3.equals(p) ? "HTTP/3" : P_WG.equals(p) ? "WireGuard" : P_GOOL.equals(p) ? L.t("gool (WG داخل MASQUE)") : "HTTP/2";
    }

    public static File dir(Context c) {
        File d = new File(c.getFilesDir(), "aether");
        if (!d.isDirectory()) //noinspection ResultOfMethodCallIgnored
            d.mkdirs();
        return d;
    }

    public static File masqueToml(Context c) { return new File(dir(c), "masque.toml"); }
    public static File wgToml(Context c) { return new File(dir(c), "wg.toml"); }
    public static File goolToml(Context c) { return new File(dir(c), "masque-gool.toml"); }

    public static String diag(Context c) {
        return "aether: available=" + available(c) + " proto=" + proto(c) + " sni=" + sni(c) + " viaBridge=" + viaBridge(c)
                + " exitNotIR=" + exitNotIR(c) + " ids:" + (masqueToml(c).isFile() ? " masque" : "")
                + (wgToml(c).isFile() ? " wg" : "") + (goolToml(c).isFile() ? " gool" : "")
                + (O76VpnService.aetherExit.isEmpty() ? "" : " exit=" + O76VpnService.aetherExit) + "\n";
    }

    // ---------------- best bridge ----------------
    /** url of the best working bridge that reached a server abroad (intl=1), or null */
    public static String bestIntlBridge(Context c) {
        for (org.json.JSONObject o : Bridges.results(c, "bridgeRes")) {
            if (o.optInt("ok", -1) != 1 || Bridges.coolingDown(o) || Bridges.intl(o) != 1) continue;
            String u = o.optString("u", o.optString("k"));
            if (!u.isEmpty()) return u;
        }
        return null;
    }

    // ---------------- identity ----------------
    /**
     * Makes sure the identity the chosen protocol needs exists in filesDir/aether. MASQUE (h2/h3) and gool reuse our
     * WARP account (converted, no API call). WireGuard and gool's inner hop need a WG-registered identity: registered
     * once with "--register wg|gool" (through the best intl=1 bridge when there is one) and kept.
     * Returns null on success, else an error text.
     */
    public static String prepareIdentity(Context c) {
        String p = proto(c);
        if (!P_WG.equals(p)) {
            String e = convertIdentity(c);
            if (e != null) return e;
        }
        if (P_WG.equals(p) && !wgToml(c).isFile()) return register(c, "wg");
        if (P_GOOL.equals(p) && !goolToml(c).isFile()) return register(c, "gool");
        return null;
    }

    /** o76core aetherid when masque.toml is missing, older than config.json, or older than 300 days */
    static String convertIdentity(Context c) {
        File cfg = Core.cfg(c), t = masqueToml(c);
        if (!Core.hasConfig(c)) return L.t("حساب WARP وجود ندارد؛ اول ثبت‌نام کنید");
        boolean stale = !t.isFile() || t.lastModified() < cfg.lastModified()
                || System.currentTimeMillis() - t.lastModified() > 300L * 24 * 3600 * 1000;
        if (!stale) return null;
        try {
            Process p = Core.start(c, "aetherid", "-in", cfg.getAbsolutePath(), "-out", t.getAbsolutePath());
            final String[] err = {null};
            int code = Core.pump(p, line -> { if (line.startsWith("ERR")) err[0] = line.substring(3).trim(); });
            if (code != 0 || !t.isFile()) return L.t("تبدیل هویت WARP برای Aether ناموفق بود: ") + (err[0] == null ? L.t("کد ") + code : err[0]);
            // the lastconn cache belongs to the previous identity
            //noinspection ResultOfMethodCallIgnored
            new File(dir(c), "masque-lastconn.toml").delete();
            Core.log(L.t("Aether: هویت WARP موجود تبدیل شد (بدون ثبت دستگاه جدید)"));
            return null;
        } catch (Exception e) {
            return L.t("تبدیل هویت: ") + e.getMessage();
        }
    }

    /** one-time "--register wg|gool" (via the best intl=1 bridge when available); never replaces an identity */
    static String register(Context c, String which) {
        String up = bestIntlBridge(c);
        Core.log(L.t("Aether: ثبت هویت ") + which + (up == null ? L.t(" (مستقیم)") : L.t(" از طریق پل ") + Bridges.keyOf(up)) + " …");
        List<String> a = new ArrayList<>();
        a.add("--register"); a.add(which);
        a.add("--masque-config"); a.add(masqueToml(c).getAbsolutePath());
        if ("wg".equals(which)) { a.add("--wg-config"); a.add(wgToml(c).getAbsolutePath()); }
        a.add("--fragment");
        if (up == null) { a.add("--api-address"); a.add("162.159.137.105"); } // direct: no system DNS needed (musl)
        a.add("--log-level"); a.add("info");
        try {
            Process p = start(c, a, up, false);
            final String[] last = {""};
            Thread killer = new Thread(() -> {
                try { Thread.sleep(120_000); p.destroy(); } catch (InterruptedException ignored) { }
            });
            killer.start();
            int code = Core.pump(p, line -> {
                Line l = parse(line);
                if (l.msg.startsWith("Error") || "ERROR".equals(l.level) || "WARN".equals(l.level) || l.msg.contains("[+]")) {
                    Core.log("Aether: " + l.msg);
                }
                last[0] = l.msg;
            });
            killer.interrupt();
            File want = "wg".equals(which) ? wgToml(c) : goolToml(c);
            if (code == 0 && want.isFile()) {
                Core.log(L.t("Aether: هویت ") + which + L.t(" ساخته و ذخیره شد"));
                return null;
            }
            return L.t("ثبت هویت ") + which + L.t(" برای Aether ناموفق بود (کد ") + code + "): " + last[0];
        } catch (Exception e) {
            return L.t("ثبت هویت ") + which + ": " + e.getMessage();
        }
    }

    // ---------------- process ----------------
    /** starts libaether.so headless: stdin closed (EOF, as /dev/null), output merged, no environment proxy */
    static Process start(Context c, List<String> args, String upstream, boolean tunnel) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(bin(c).getAbsolutePath());
        cmd.addAll(args);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir(c));
        pb.redirectErrorStream(true);
        Map<String, String> env = pb.environment();
        for (String k : new String[]{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "RUST_LOG"}) env.remove(k);
        env.put("AETHER_REPROVISION", "0");   // never register a new device on its own
        env.put("NO_COLOR", "1");
        env.put("HOME", dir(c).getAbsolutePath());
        if (upstream != null) env.put("AETHER_UPSTREAM", upstream); // env, not argv: may carry proxy credentials
        Process p = pb.start();
        try { p.getOutputStream().close(); } catch (Exception ignored) { } // stdin = EOF: never waits for a question
        return p;
    }

    public static int freePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return s.getLocalPort();
        }
    }

    /** headless tunnel arguments (see PLAN): every interactive choice is a flag */
    static List<String> tunnelArgs(Context c, int port, boolean exitLoc) {
        String p = proto(c);
        List<String> a = new ArrayList<>();
        switch (p) {
            case P_WG:
                a.add("--wg"); a.add("--noize"); a.add("balanced");
                a.add("--wg-config"); a.add(wgToml(c).getAbsolutePath());
                break;
            case P_GOOL:
                a.add("--gool"); a.add("--h2"); // outer hop over TCP: UDP/QUIC is blocked on many Iranian networks
                a.add("--noize"); a.add("balanced");
                a.add("--masque-config"); a.add(masqueToml(c).getAbsolutePath()); // + masque-gool.toml beside it
                a.add("--fragment"); a.add("--fragment-size"); a.add("8-16"); a.add("--fragment-delay"); a.add("2-10");
                a.add("--masque-sni"); a.add(sni(c));
                break;
            case P_H3:
                a.add("--masque"); a.add("--h3"); a.add("--noize"); a.add("firewall");
                a.add("--masque-config"); a.add(masqueToml(c).getAbsolutePath());
                a.add("--masque-sni"); a.add(sni(c));
                break;
            default:
                a.add("--masque"); a.add("--h2"); a.add("--noize"); a.add("firewall");
                a.add("--fragment"); a.add("--fragment-size"); a.add("8-16"); a.add("--fragment-delay"); a.add("2-10");
                a.add("--masque-config"); a.add(masqueToml(c).getAbsolutePath());
                a.add("--masque-sni"); a.add(sni(c));
        }
        a.add("--scan"); a.add("balanced");
        a.add("-4");
        a.add("--quick-reconnect");
        a.add("--bind"); a.add("127.0.0.1:" + port);
        a.add("--startup-secs"); a.add("30");
        a.add("--reconnect-secs"); a.add("2");
        a.add("--dns"); a.add("1.1.1.1,1.0.0.1");
        a.add("--api-address"); a.add("162.159.137.105"); // musl has no resolv.conf on Android: no system DNS needed
        a.add("--stats"); a.add("--stats-secs"); a.add("5");
        a.add("--log-level"); a.add("info");
        if (exitLoc) { a.add("--exit-loc"); a.add("!IR"); }
        return a;
    }

    /** kills Aether processes left over from a previous app process (same uid; they would hold their port) */
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
                int z = cl.indexOf('\0');
                if (z >= 0) cl = cl.substring(0, z);
                if (cl.equals(me)) {
                    android.os.Process.killProcess(Integer.parseInt(n));
                    Core.log(L.t("Aether: پردازش جامانده بسته شد (pid ") + n + ")");
                }
            } catch (Exception ignored) { }
        }
    }

    // ---------------- log lines ----------------
    static final class Line {
        String level = "", target = "", msg = "";
    }

    // "[2026-11-22T18:14:03Z INFO  aether::socks] msg" or "[Sun 2026-11-22 9:47 PM (UTC+03:30) INFO  aether] msg"
    private static final Pattern LP = Pattern.compile("^\\[.*?\\b(INFO|WARN|ERROR|DEBUG|TRACE)\\s+([\\w:]+)\\]\\s?(.*)$");
    private static final Pattern ADDR = Pattern.compile("(\\d{1,3}(?:\\.\\d{1,3}){3}:\\d+|\\[[0-9a-fA-F:]+\\]:\\d+)");

    static Line parse(String s) {
        Line l = new Line();
        Matcher m = LP.matcher(s);
        if (m.matches()) {
            l.level = m.group(1);
            l.target = m.group(2);
            l.msg = m.group(3).trim();
        } else {
            l.msg = s.trim();
        }
        return l;
    }

    static String addrIn(String s) {
        Matcher m = ADDR.matcher(s);
        return m.find() ? m.group(1) : "";
    }

    /** One running Aether tunnel process and what its log said so far. */
    public static final class Run {
        Process p;
        int port;
        String proto;
        /** started with --exit-loc !IR (cleared once the IR fallback was handled) */
        volatile boolean exitLoc;
        /** v1.6.1 startup / reconnect state machine (pure Java, unit-tested) */
        final AetherWatch w = new AetherWatch(System.currentTimeMillis());
        volatile boolean validated, socksUp, dead, everUp, selected;
        volatile int found;
        volatile long downSince, startedAt;
        volatile String endpoint = "", transport = "", exit = "", lastErr = "", stats = "";
        /** bridge in use ("scheme://ip:port", no credentials) or null when direct */
        String upKey;
        private int statN, candN;

        /** "tunnel validated" + "socks5 server listening"; the exit line is not waited for */
        boolean up() { return validated && socksUp && !dead; }

        void onLine(String raw) {
            Line l = parse(raw);
            String m = l.msg;
            if (m.isEmpty()) return;
            boolean log = true;
            boolean wasValidated = w.validated();
            w.onMsg(m, System.currentTimeMillis());
            validated = w.validated();
            socksUp = w.socksUp();
            found = w.found();
            if (!w.exit().isEmpty()) exit = w.exit();
            if (validated && !wasValidated) {
                downSince = 0;
                if (everUp) Core.log(L.t("Aether: تونل دوباره برقرار شد"));
            } else if (!validated && wasValidated) {
                downSince = System.currentTimeMillis();
            }
            if (validated && socksUp) everUp = true;
            if (m.contains("selected MASQUE gateway") || m.contains("using cloudflare edge") || m.contains("selected WireGuard")
                    || m.contains("selected wireguard")) {
                String a = addrIn(m);
                if (!a.isEmpty()) endpoint = a;
                selected = true;
            } else if (m.contains("transport: HTTP/2")) {
                transport = "h2";
            } else if (m.contains("transport: HTTP/3")) {
                transport = "h3";
            } else if (m.startsWith("[=] up")) {
                stats = m;
                log = statN++ % 12 == 0; // stats every 5 s: one line a minute in the log
            } else if (m.contains("candidate ok")) {
                log = candN++ < 400; // bounded
            }
            if (m.startsWith("Error") || "ERROR".equals(l.level)) lastErr = m;
            if (log) Core.log("Aether: " + ("WARN".equals(l.level) || "ERROR".equals(l.level) ? l.level + " " : "") + m);
        }
    }

    /** thrown by waitUp when --exit-loc !IR rejected the (working) tunnel twice */
    static final class ExitIrFallback extends Exception {
        ExitIrFallback() { super("exit IR rejected twice"); }
    }

    /**
     * Starts the tunnel and returns once both "tunnel validated" and "socks5 server listening" were seen.
     * Throws (after killing the process) when the AetherWatch rules give up (idle 60 s with nothing happening, or the
     * 240 s hard cap without a validation), the process exits, or {@code cancelled} says the session is gone.
     * v1.6.1: two "exit location IR rejected" with «خروجی غیر ایران» on -> option off, restart once without --exit-loc.
     */
    public static Run startTunnel(Context c, Core.Cancel cancelled) throws Exception {
        String err = prepareIdentity(c);
        if (err != null) throw new Exception(err);
        Run r = launch(c, exitNotIR(c));
        try {
            waitUp(r, cancelled);
        } catch (ExitIrFallback f) {
            stop(r);
            disableExitLocAfterIR(c);
            r = launch(c, false);
            waitUp(r, cancelled);
        }
        Core.log(L.t("Aether: آماده در ") + (System.currentTimeMillis() - r.startedAt) / 1000 + L.t(" ثانیه — ") + protoLabel(r.proto)
                + " " + r.endpoint + (r.exit.isEmpty() ? "" : L.t(" — خروجی ") + r.exit));
        return r;
    }

    private static Run launch(Context c, boolean exitLoc) throws Exception {
        final Run r = new Run();
        r.port = freePort();
        r.proto = proto(c);
        r.exitLoc = exitLoc;
        String up = bridgeApplies(c) ? bestIntlBridge(c) : null;
        if (bridgeApplies(c) && up == null) Core.log(L.t("Aether: «از طریق پل» روشن است ولی پل سالمی با دسترسی خارج (intl=1) نیست ← مستقیم"));
        List<String> args = tunnelArgs(c, r.port, exitLoc);
        Core.log("Aether v" + VERSION + L.t(": شروع ") + protoLabel(r.proto) + " SNI=" + sni(c) + " socks=127.0.0.1:" + r.port
                + (up != null ? L.t(" از طریق پل ") + Bridges.keyOf(up) : "") + (exitLoc ? L.t(" خروجی≠IR") : ""));
        r.upKey = up == null ? null : Bridges.keyOf(up);
        r.startedAt = r.w.startedAt;
        r.p = start(c, args, up, true);
        final Process p = r.p;
        Thread t = new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) r.onLine(line);
            } catch (Exception ignored) { }
            int code = -1;
            try { code = p.waitFor(); } catch (InterruptedException ignored) { }
            r.dead = true;
            Core.log(L.t("Aether: پردازش پایان یافت (کد ") + code + ")" + (r.lastErr.isEmpty() ? "" : " — " + r.lastErr));
        }, "o76-aether-log");
        t.start();
        return r;
    }

    private static void waitUp(Run r, Core.Cancel cancelled) throws Exception {
        while (!r.up()) {
            if (cancelled.getAsBoolean()) { stop(r); throw new InterruptedException("cancelled"); }
            if (r.exitLoc && r.w.exitFallback()) throw new ExitIrFallback();
            if (r.dead) {
                stop(r);
                throw new Exception(L.t("هستهٔ Aether متوقف شد") + (r.lastErr.isEmpty() ? "" : ": " + r.lastErr));
            }
            String why = r.w.check(System.currentTimeMillis());
            if (why != null) {
                stop(r);
                long secs = (System.currentTimeMillis() - r.startedAt) / 1000;
                String fa = "idle".equals(why) ? L.t("۶۰ ثانیه بدون هیچ پیشرفتی (دروازهٔ پاسخ‌گو پیدا نشد)")
                        : "hard-cap".equals(why) ? L.t("۴ دقیقه بدون تأیید تونل")
                        : L.t("۲ دقیقه پس از قطع، تونل دوباره تأیید نشد");
                Core.log("Aether: " + fa + L.t(" — پس از ") + secs + L.t(" ثانیه متوقف شد (مرحله ") + r.w.phaseName() + L.t("، ") + r.found + L.t(" دروازهٔ پاسخ‌گو)"));
                throw new Exception(L.t("Aether تونل را برقرار نکرد (") + fa + L.t(") — پروتکل/SNI دیگر یا «از طریق پل» را امتحان کنید، یا حالت دیگری را انتخاب کنید"));
            }
            Thread.sleep(250);
        }
    }

    public static void stop(Run r) {
        if (r == null || r.p == null) return;
        try { r.p.destroy(); } catch (Exception ignored) { } // SIGTERM
        final Process p = r.p;
        new Thread(() -> {
            try {
                Thread.sleep(1500);
                p.exitValue();
            } catch (IllegalThreadStateException e) {
                // still alive after SIGTERM: SIGKILL via its pid (java.lang.Process has no pid() before API 33)
                try {
                    java.lang.reflect.Field f = p.getClass().getDeclaredField("pid");
                    f.setAccessible(true);
                    android.os.Process.killProcess(f.getInt(p));
                } catch (Exception ignored) { }
            } catch (Exception ignored) { }
        }, "o76-aether-kill").start();
    }
}
