package com.o76one.app;

import android.app.Application;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * v1.5 application: persistent log (files/o76.log, rotated at 512 KB to o76.log.1) that survives process restarts,
 * plus an uncaught-exception handler that writes the stack trace to that log before the default handler runs.
 */
public class O76App extends Application {
    public static final long MAX_LOG = 512L * 1024;
    private static final int RING = 400;

    private static final Object LOCK = new Object();
    private static final ArrayDeque<String> ring = new ArrayDeque<>();
    private static volatile File logFile;
    private static final ThreadLocal<SimpleDateFormat> FMT =
            new ThreadLocal<SimpleDateFormat>() { // v1.8.2: ThreadLocal.withInitial is API 26
                @Override protected SimpleDateFormat initialValue() { return new SimpleDateFormat("HH:mm:ss", Locale.US); }
            };

    @Override
    public void onCreate() {
        super.onCreate();
        L.init(this); // v1.8.1 UI language
        // v1.8.2: Worker mode was removed; forget everything it stored (incl. a Cloudflare API token, if any)
        android.content.SharedPreferences sp = getSharedPreferences("o76", MODE_PRIVATE);
        android.content.SharedPreferences.Editor ed = null;
        for (String k : new String[]{"wToken", "wUuid", "wHost", "wName", "wPath", "wPorts", "wProxyIp", "wRes", "wSni", "wSub",
                "wViaBridge", "wEd", "wScanAt"}) {
            if (sp.contains(k)) { if (ed == null) ed = sp.edit(); ed.remove(k); }
        }
        if (ed != null) ed.apply();
        logFile = new File(getFilesDir(), "o76.log");
        final Thread.UncaughtExceptionHandler def = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            try {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                log("CRASH in thread " + t.getName() + ": " + sw);
            } catch (Throwable ignored) { }
            if (def != null) def.uncaughtException(t, e);
            else System.exit(2);
        });
        String ver = "";
        try { ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName; } catch (Exception ignored) { }
        log("— app start " + ver + " (pid " + android.os.Process.myPid() + ")");
    }

    /** Appends one line (prefixed HH:mm:ss) to the in-memory ring and the log file. Thread-safe. */
    public static void log(String line) {
        String s = FMT.get().format(new Date()) + " " + (line == null ? "null" : line);
        synchronized (LOCK) {
            ring.addLast(s);
            while (ring.size() > RING) ring.removeFirst();
            File f = logFile;
            if (f == null) return;
            try {
                if (f.length() > MAX_LOG) {
                    File old = new File(f.getPath() + ".1");
                    if (old.exists()) //noinspection ResultOfMethodCallIgnored
                        old.delete();
                    //noinspection ResultOfMethodCallIgnored
                    f.renameTo(old);
                }
                try (FileOutputStream o = new FileOutputStream(f, true)) {
                    o.write((s + "\n").getBytes(StandardCharsets.UTF_8));
                }
            } catch (Exception ignored) { }
        }
    }

    /** Last `lines` lines of the persistent log (oldest first); falls back to the in-memory ring. */
    public static String tail(int lines) {
        if (lines <= 0) return "";
        synchronized (LOCK) {
            List<String> l = new ArrayList<>();
            File f = logFile;
            if (f != null) {
                l.addAll(lastLines(f, lines));
                if (l.size() < lines) {
                    List<String> older = lastLines(new File(f.getPath() + ".1"), lines - l.size());
                    older.addAll(l);
                    l = older;
                }
            }
            if (l.isEmpty()) l.addAll(ring);
            int from = Math.max(0, l.size() - lines);
            StringBuilder sb = new StringBuilder();
            for (int i = from; i < l.size(); i++) sb.append(l.get(i)).append('\n');
            return sb.toString();
        }
    }

    /** The whole persistent log (o76.log.1 then o76.log), oldest first. */
    public static String readAll() {
        synchronized (LOCK) {
            File f = logFile;
            if (f == null) {
                StringBuilder sb = new StringBuilder();
                for (String s : ring) sb.append(s).append('\n');
                return sb.toString();
            }
            return read(new File(f.getPath() + ".1")) + read(f);
        }
    }

    /** Deletes the log files and the in-memory ring. */
    public static void clear() {
        synchronized (LOCK) {
            ring.clear();
            File f = logFile;
            if (f != null) {
                //noinspection ResultOfMethodCallIgnored
                f.delete();
                //noinspection ResultOfMethodCallIgnored
                new File(f.getPath() + ".1").delete();
            }
        }
    }

    /** In-memory ring (this process only), oldest first. */
    static List<String> ringLines() {
        synchronized (LOCK) { return new ArrayList<>(ring); }
    }

    private static String read(File f) {
        try {
            if (!f.exists()) return "";
            return new String(readAll(f), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    /** last n lines of a file, reading only its end (lines are short; 300 bytes per line is plenty) */
    private static List<String> lastLines(File f, int n) {
        List<String> r = new ArrayList<>();
        if (!f.exists() || n <= 0) return r;
        try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
            long len = raf.length();
            long want = Math.min(len, Math.max(16384L, (long) n * 300));
            raf.seek(len - want);
            byte[] b = new byte[(int) want];
            raf.readFully(b);
            String s = new String(b, StandardCharsets.UTF_8);
            String[] parts = s.split("\n");
            int start = want < len ? 1 : 0; // first piece may be a partial line
            for (int i = start; i < parts.length; i++) if (!parts[i].isEmpty()) r.add(parts[i]);
            if (r.size() > n) r = new ArrayList<>(r.subList(r.size() - n, r.size()));
        } catch (Exception ignored) { }
        return r;
    }

    /** whole file as bytes (java.nio.file.Files is API 26; minSdk is 21) */
    static byte[] readAll(File f) throws java.io.IOException {
        try (java.io.FileInputStream in = new java.io.FileInputStream(f)) {
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream((int) Math.min(Math.max(f.length(), 16), 1 << 24));
            byte[] b = new byte[16384];
            int n;
            while ((n = in.read(b)) > 0) bo.write(b, 0, n);
            return bo.toByteArray();
        }
    }
}
