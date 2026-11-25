package com.o76one.app;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * v1.7 "Firefox" mode: signs in to the user's OWN Firefox account and uses the Firefox / Mozilla VPN proxy network
 * (HTTP/3 or HTTP/2 CONNECT to Fastly MASQUE edges), the same path the Predator VPN client uses. The core is
 * lib/<abi>/libfpn.so: a small front for the Predator VPN core (erfan-tahvilian/PredatorVPN v2.0.7, GPL-3.0-or-later,
 * vendored unmodified) that serves the tunnel as a local SOCKS5 port; o76core "svpn -dnsudp" carries the TUN into it.
 * No account is ever created here. The password goes to the core's stdin once and is never stored; only the
 * OAuth tokens are kept (files/fox/vault.json, app-private).
 */
public final class Fox {
    private Fox() { }

    public static final String VERSION = "2.0.7";
    public static final String REPO = "https://github.com/erfan-tahvilian/PredatorVPN";
    public static final String T_AUTO = "auto", T_H3 = "h3", T_H2 = "h2";
    /** time allowed from start to a verified tunnel (the core tries up to 5 locations, 30 s each at most) */
    static final long UP_MS = 150_000;

    public static File bin(Context c) { return new File(c.getApplicationInfo().nativeLibraryDir, "libfpn.so"); }
    public static boolean available(Context c) { File f = bin(c); return f.isFile() && f.length() > 1_000_000; }

    public static File dir(Context c) {
        File d = new File(c.getFilesDir(), "fox");
        if (!d.isDirectory()) //noinspection ResultOfMethodCallIgnored
            d.mkdirs();
        return d;
    }

    public static String transport(Context c) { return Core.prefs(c).getString("fTransport", T_AUTO); }
    public static void setTransport(Context c, String t) { Core.prefs(c).edit().putString("fTransport", t).apply(); }
    public static String server(Context c) { return Core.prefs(c).getString("fServer", "REC"); }
    public static void setServer(Context c, String s) { Core.prefs(c).edit().putString("fServer", s).apply(); }
    public static boolean recovery(Context c) { return Core.prefs(c).getBoolean("fRecovery", false); }
    public static void setRecovery(Context c, boolean on) { Core.prefs(c).edit().putBoolean("fRecovery", on).apply(); }
    public static String email(Context c) { return Core.prefs(c).getString("fEmail", ""); }
    public static boolean signedIn(Context c) { return !email(c).isEmpty() && new File(dir(c), "vault.json").isFile(); }
    static void setEmail(Context c, String e) { Core.prefs(c).edit().putString("fEmail", e == null ? "" : e).apply(); }
    /** cached location list: lines "id|code|country|city" */
    public static String servers(Context c) { return Core.prefs(c).getString("fServers", ""); }
    static void setServers(Context c, String s) { Core.prefs(c).edit().putString("fServers", s).apply(); }

    public static String transportLabel(String t) {
        return T_H3.equals(t) ? "HTTP/3" : T_H2.equals(t) ? "HTTP/2" : L.t("خودکار (HTTP/3 سپس HTTP/2)");
    }

    public static String diag(Context c) {
        return "fox: available=" + available(c) + " signedIn=" + signedIn(c) + " transport=" + transport(c)
                + " server=" + server(c) + " recovery=" + recovery(c) + "\n";
    }

    /** starts libfpn.so; stdin stays open (login answers), output merged */
    static Process start(Context c, List<String> args) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(bin(c).getAbsolutePath());
        cmd.addAll(args);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir(c));
        pb.redirectErrorStream(true);
        Map<String, String> env = pb.environment();
        for (String k : new String[]{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"}) env.remove(k);
        env.put("HOME", dir(c).getAbsolutePath());
        return pb.start();
    }

    static List<String> base(Context c, String cmd) {
        List<String> a = new ArrayList<>();
        a.add(cmd);
        a.add("-dir"); a.add(dir(c).getAbsolutePath());
        String dns = Core.systemDns(c);
        if (dns != null && !dns.isEmpty()) { a.add("-dns"); a.add(dns.split(",")[0].trim()); }
        if (recovery(c)) a.add("-recovery");
        return a;
    }

    /** blocking: refreshes the public location list (no account needed); returns count or throws */
    public static int refreshServers(Context c) throws Exception {
        Process p = start(c, base(c, "servers"));
        try { p.getOutputStream().close(); } catch (Exception ignored) { }
        StringBuilder sb = new StringBuilder();
        String err = "";
        int n = -1;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
            String l;
            while ((l = br.readLine()) != null) {
                if (l.startsWith("SERVER ")) sb.append(l.substring(7)).append('\n');
                else if (l.startsWith("OK ")) { try { n = Integer.parseInt(l.substring(3).trim()); } catch (Exception ignored) { } }
                else if (l.startsWith("ERR ")) err = l.substring(4);
            }
        }
        p.waitFor();
        if (n < 0) throw new Exception(err.isEmpty() ? L.t("فهرست مکان‌ها دریافت نشد") : err);
        setServers(c, sb.toString());
        return n;
    }

    /** logout: forgets the tokens on this phone (the account itself is untouched) */
    public static void logout(Context c) {
        try {
            Process p = start(c, base(c, "logout"));
            try { p.getOutputStream().close(); } catch (Exception ignored) { }
            Core.pump(p, l -> { });
        } catch (Exception ignored) { }
        //noinspection ResultOfMethodCallIgnored
        new File(dir(c), "vault.json").delete();
        setEmail(c, "");
        Core.log(L.t("Firefox: از حساب خارج شدید (توکن‌ها از این گوشی پاک شد)"));
    }

    // ---------------- tunnel ----------------
    public static final class Run {
        Process p;
        int port;
        volatile boolean up, dead;
        volatile String proto = "", loc = "", exit = "", err = "", quota = "";
        long startedAt = System.currentTimeMillis();
        volatile long downAt;

        void onLine(Context c, String l) {
            if (l.startsWith("UP ")) {
                String[] s = l.substring(3).split("\\|", -1);
                proto = s.length > 0 ? s[0] : "";
                loc = s.length > 1 ? s[1] : "";
                exit = s.length > 2 ? s[2] : "";
                up = true;
            } else if (l.startsWith("QUOTA ")) {
                quota = l.substring(6).trim();
                Core.log(L.t("Firefox: سهمیه ") + quotaFa(quota));
            } else if (l.startsWith("DOWN ")) {
                err = l.substring(5);
                downAt = System.currentTimeMillis();
                Core.log(L.t("Firefox: تونل بسته شد — ") + err);
            } else if (l.startsWith("ERR ")) {
                err = l.substring(4);
                Core.log("Firefox: " + err);
                if (err.contains("not signed in") || err.toLowerCase().contains("sign in again")) setEmail(c, "");
            } else if (l.startsWith("LOG ")) {
                String m = l.substring(4);
                if (m.toLowerCase().contains("sign in again") || m.contains("session expired")) setEmail(c, "");
                Core.log("Firefox: " + m);
                if (m.startsWith("error ")) err = m.substring(6);
            } else if (!l.startsWith("STAT ")) {
                Core.log("Firefox: " + l);
            }
        }
    }

    /** v1.8.5: the monthly quota is used up ("limit 0 reset"); reconnecting cannot help then */
    static boolean quotaEmpty(String q) {
        if (q == null || q.isEmpty()) return false;
        String[] s = q.split(" ");
        try { return s.length > 1 && Long.parseLong(s[1]) <= 0; } catch (Exception e) { return false; }
    }

    /** "limit remaining reset" (bytes, reset as the service gives it) -> Persian */
    static String quotaFa(String q) {
        String[] s = q.split(" ");
        try {
            long lim = Long.parseLong(s[0]), rem = Long.parseLong(s[1]);
            return L.t("باقی‌مانده ") + Core.fmtBytes(rem) + L.t(" از ") + Core.fmtBytes(lim);
        } catch (Exception e) {
            return q;
        }
    }

    public static Run startTunnel(Context c, Core.Cancel cancelled) throws Exception {
        return startTunnel(c, cancelled, 0);
    }

    /**
     * v1.8.5: port > 0 restarts the core on the same SOCKS port, so o76core svpn (and the TUN) keep running while
     * only libfpn is restarted. Also sends a keep-alive (TLS handshake through its own SOCKS port) every 20 s.
     */
    public static Run startTunnel(Context c, Core.Cancel cancelled, int port) throws Exception {
        if (!signedIn(c)) throw new Exception(L.t("برای حالت Firefox اول در صفحهٔ «Firefox» با حساب فایرفاکس خودتان وارد شوید"));
        killStale(c);
        final Run r = new Run();
        r.port = port > 0 ? port : Aether.freePort();
        List<String> a = base(c, "run");
        a.add("-port"); a.add(String.valueOf(r.port));
        a.add("-keepalive"); a.add("20s");
        a.add("-transport"); a.add(transport(c));
        a.add("-server"); a.add(server(c));
        Core.log("Firefox v" + VERSION + L.t(": شروع ") + transportLabel(transport(c)) + L.t(" مکان=") + server(c) + " socks=127.0.0.1:" + r.port
                + (recovery(c) ? L.t(" (بازیابی حساب از طریق رله‌ها روشن)") : ""));
        r.p = start(c, a);
        try { r.p.getOutputStream().close(); } catch (Exception ignored) { }
        final Process p = r.p;
        new Thread(() -> {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) { line = line.trim(); if (!line.isEmpty()) r.onLine(c, line); }
            } catch (Exception ignored) { }
            int code = -1;
            try { code = p.waitFor(); } catch (InterruptedException ignored) { }
            r.dead = true;
            Core.log(L.t("Firefox: پردازش پایان یافت (کد ") + code + ")");
        }, "o76-fox-log").start();
        while (!r.up) {
            if (cancelled.getAsBoolean()) { stop(r); throw new InterruptedException("cancelled"); }
            if (r.dead) throw new Exception(L.t("Firefox وصل نشد") + (r.err.isEmpty() ? "" : ": " + r.err));
            if (System.currentTimeMillis() - r.startedAt > UP_MS) {
                stop(r);
                throw new Exception(L.t("Firefox در ") + UP_MS / 1000 + L.t(" ثانیه تونل تأییدشده نساخت") + (r.err.isEmpty() ? "" : " (" + r.err + ")"));
            }
            Thread.sleep(250);
        }
        Core.log(L.t("Firefox: آماده در ") + (System.currentTimeMillis() - r.startedAt) / 1000 + L.t(" ثانیه — ") + r.proto.toUpperCase()
                + (r.loc.isEmpty() ? "" : " " + r.loc) + (r.exit.isEmpty() ? "" : L.t(" — خروجی ") + r.exit));
        return r;
    }

    /**
     * v1.8.5: stops the core and waits (max ~1.2 s) until it is gone, killing it if SIGTERM was not enough, so a
     * restart on the same SOCKS port can follow at once.
     */
    public static void stopWait(Run r) {
        if (r == null || r.p == null) return;
        try { r.p.destroy(); } catch (Exception ignored) { }
        long end = System.currentTimeMillis() + 800;
        while (System.currentTimeMillis() < end) {
            try { r.p.exitValue(); return; } catch (IllegalThreadStateException e) {
                try { Thread.sleep(50); } catch (InterruptedException ie) { break; }
            } catch (Exception e) { return; }
        }
        try {
            java.lang.reflect.Field f = r.p.getClass().getDeclaredField("pid");
            f.setAccessible(true);
            android.os.Process.killProcess(f.getInt(r.p));
        } catch (Exception ignored) { }
        end = System.currentTimeMillis() + 400;
        while (System.currentTimeMillis() < end) {
            try { r.p.exitValue(); return; } catch (IllegalThreadStateException e) {
                try { Thread.sleep(50); } catch (InterruptedException ie) { return; }
            } catch (Exception e) { return; }
        }
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
        }, "o76-fox-kill").start();
    }

    /** kills "libfpn.so run" processes left from a previous app process */
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
                String[] parts = cl.split("\0");
                if (parts.length > 1 && parts[0].equals(me) && "run".equals(parts[1])) {
                    android.os.Process.killProcess(Integer.parseInt(n));
                }
            } catch (Exception ignored) { }
        }
    }

    // ---------------- sign-in (own account) ----------------
    public interface LoginUi {
        /** e-mail / authenticator code; return null to cancel. Called off the UI thread, may block. */
        String askCode(String method);
        /** the provider's image CAPTCHA (a file); the human types what it shows; null cancels */
        String askCaptcha(File image);
        void status(String s);
    }

    /** v1.8.7: Persian/Arabic keyboards type ۰-۹ / ٠-٩, which the provider rejects; send ASCII digits, no spaces */
    static String latin(String s) {
        StringBuilder b = new StringBuilder();
        for (char ch : s.trim().toCharArray()) {
            if (ch >= '\u06F0' && ch <= '\u06F9') ch = (char) ('0' + (ch - '\u06F0'));
            else if (ch >= '\u0660' && ch <= '\u0669') ch = (char) ('0' + (ch - '\u0660'));
            if (!Character.isWhitespace(ch) && ch != '\u200C' && ch != '\u200F' && ch != '\u200E') b.append(ch);
        }
        return b.toString();
    }

    /** blocking: signs in with the user's existing account; returns null on success or a Persian error */
    public static String login(Context c, String email, String password, LoginUi ui) {
        Process p = null;
        try {
            p = start(c, base(c, "login"));
            OutputStream o = p.getOutputStream();
            o.write((email.trim() + "\n" + password + "\n").getBytes(StandardCharsets.UTF_8));
            o.flush();
            String err = "", ok = null;
            try (BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String l;
                while ((l = br.readLine()) != null) {
                    l = l.trim();
                    if (l.startsWith("NEEDCODE")) {
                        String m = l.length() > 9 ? l.substring(9) : "";
                        String code = ui.askCode(m);
                        if (code == null) { p.destroy(); return L.t("ورود لغو شد"); }
                        o.write((latin(code) + "\n").getBytes(StandardCharsets.UTF_8));
                        o.flush();
                        ui.status(L.t("بررسی کد…"));
                    } else if (l.startsWith("CAPTCHA ")) {
                        String ans = ui.askCaptcha(new File(l.substring(8).trim()));
                        if (ans == null) { p.destroy(); return L.t("ورود لغو شد"); }
                        o.write((latin(ans) + "\n").getBytes(StandardCharsets.UTF_8));
                        o.flush();
                        ui.status(L.t("بررسی تصویر…"));
                    } else if (l.startsWith("OK")) {
                        ok = l.length() > 3 ? l.substring(3).trim() : email.trim();
                    } else if (l.startsWith("ERR ")) {
                        err = l.substring(4);
                    } else if (l.startsWith("LOG ")) {
                        String m = l.substring(4);
                        if (m.startsWith("error ")) { err = m.substring(6); ui.status(L.t("خطا: ") + err); }
                    }
                }
            }
            p.waitFor();
            //noinspection ResultOfMethodCallIgnored
            new File(dir(c), "captcha.img").delete();
            if (ok != null) {
                setEmail(c, ok.isEmpty() ? email.trim() : ok);
                Core.log(L.t("Firefox: ورود موفق با حساب خودتان"));
                try { refreshServers(c); } catch (Exception ignored) { }
                return null;
            }
            Core.log(L.t("Firefox: ورود ناموفق — ") + err);
            return err.isEmpty() ? L.t("ورود ناموفق بود") : err;
        } catch (Exception e) {
            if (p != null) p.destroy();
            return e.getMessage();
        }
    }
}
