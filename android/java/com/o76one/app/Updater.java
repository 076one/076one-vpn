package com.o76one.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;

/**
 * v1.8.5 in-app updater (Android side). Manifest: {@link UpdCore#MANIFEST_URL} (public repo 076one/076one-vpn, branch
 * main, release/latest.json). While the VPN is connected through a mode with a local SOCKS5 port the manifest and the
 * APK are fetched through the app's own tunnel (GitHub may be filtered); otherwise, or if that fails, directly. The
 * APK must match latest.json's SHA-256 and be signed with the same certificate as the installed app; then the system
 * installer opens (content:// URI from ApkProvider on Android 7+, file:// on 5-6; "install unknown apps" permission
 * asked for on 8+).
 */
public final class Updater {
    private Updater() { }

    static final String MIME = "application/vnd.android.package-archive";
    static final long DAY = 24L * 3600 * 1000;
    static volatile boolean busy;

    public static boolean autoCheck(Context c) { return Core.prefs(c).getBoolean("updAuto", true); }
    public static void setAutoCheck(Context c, boolean on) { Core.prefs(c).edit().putBoolean("updAuto", on).apply(); }

    static int ownCode(Context c) {
        try {
            //noinspection deprecation
            return c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionCode;
        } catch (Exception e) {
            return 0;
        }
    }

    static String ownName(Context c) {
        try { return c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionName; } catch (Exception e) { return ""; }
    }

    /** SHA-256 of the installed app's signing certificate(s) */
    @SuppressWarnings("deprecation")
    static Set<String> ownCerts(Context c) throws Exception {
        Set<String> s = new HashSet<>();
        PackageInfo pi;
        if (Build.VERSION.SDK_INT >= 28) {
            pi = c.getPackageManager().getPackageInfo(c.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            if (pi.signingInfo != null) {
                Signature[] sg = pi.signingInfo.hasMultipleSigners() ? pi.signingInfo.getApkContentsSigners() : pi.signingInfo.getSigningCertificateHistory();
                if (sg != null) for (Signature x : sg) s.add(UpdCore.sha256(x.toByteArray()));
            }
        }
        if (s.isEmpty()) {
            pi = c.getPackageManager().getPackageInfo(c.getPackageName(), PackageManager.GET_SIGNATURES);
            if (pi.signatures != null) for (Signature x : pi.signatures) s.add(UpdCore.sha256(x.toByteArray()));
        }
        if (s.isEmpty()) throw new Exception("own signature unreadable");
        return s;
    }

    /** where the APK is downloaded: app cache (served by ApkProvider) on 7+, external cache (readable by the installer) on 5-6 */
    static File apkDir(Context c) {
        File d = null;
        if (Build.VERSION.SDK_INT < 24) d = c.getExternalCacheDir();
        if (d == null) d = c.getCacheDir();
        File u = new File(d, "update");
        //noinspection ResultOfMethodCallIgnored
        u.mkdirs();
        return u;
    }

    /** the tunnel's SOCKS port while connected (0 = none: direct) */
    static int tunnelPort() {
        int st = O76VpnService.state;
        return st == O76VpnService.ST_ON || st == O76VpnService.ST_RECONNECTING ? O76VpnService.socksPort : 0;
    }

    static void init(Context c) {
        if (UpdCore.verifier == null) UpdCore.verifier = HttpsURLConnection.getDefaultHostnameVerifier();
        UpdCore.userAgent = "076one/" + ownName(c) + " (Android " + Build.VERSION.RELEASE + ")";
    }

    interface Route { void run(int socksPort) throws Exception; }

    /** runs a network step through the tunnel first (when connected), then directly; returns the route used */
    static String viaBest(Route r) throws Exception {
        int port = tunnelPort();
        if (port > 0) {
            try {
                r.run(port);
                return "tunnel";
            } catch (Exception e) {
                if (e.getMessage() != null && e.getMessage().equals("cancelled")) throw e;
                Core.log(L.t("به‌روزرسانی: از داخل تونل نشد (") + e.getMessage() + L.t(")؛ تلاش مستقیم"));
            }
        }
        r.run(0);
        return "direct";
    }

    static UpdCore.Info fetchInfo(Context c) throws Exception {
        init(c);
        final String[] body = {null};
        String route = viaBest(port -> body[0] = UpdCore.getText(UpdCore.MANIFEST_URL, port, 256 * 1024));
        UpdCore.Info in = UpdCore.parse(body[0], Build.SUPPORTED_ABIS, L.lang());
        Core.log(L.t("به‌روزرسانی: آخرین نسخه ") + in.versionName + " (" + in.versionCode + ", " + in.abi + L.t(")؛ نصب‌شده ")
                + ownName(c) + " (" + ownCode(c) + ") [" + route + "]");
        return in;
    }

    /** v1.8.5: quiet check at app start, at most once a day; shows a dialog only when a newer version exists */
    public static void quietCheck(final Activity a) {
        if (!autoCheck(a) || busy) return;
        long last = Core.prefs(a).getLong("updLast", 0);
        long now = System.currentTimeMillis();
        if (now - last < DAY && now >= last) return;
        Core.prefs(a).edit().putLong("updLast", now).apply();
        final Context app = a.getApplicationContext();
        new Thread(() -> {
            try {
                final UpdCore.Info in = fetchInfo(app);
                if (in.versionCode <= ownCode(app) || in.minSdk > Build.VERSION.SDK_INT) return;
                new Handler(Looper.getMainLooper()).post(() -> {
                    if (!a.isFinishing()) offer(a, in);
                });
            } catch (Exception e) {
                Core.log(L.t("به‌روزرسانی: بررسی خودکار نشد — ") + e.getMessage());
            }
        }, "o76-upd-quiet").start();
    }

    /** "Check for update" button */
    public static void check(final Activity a) {
        if (busy) { toast(a, L.t("به‌روزرسانی در جریان است…")); return; }
        Core.prefs(a).edit().putLong("updLast", System.currentTimeMillis()).apply();
        final AlertDialog wait = new AlertDialog.Builder(a).setMessage(L.t("در حال بررسی به‌روزرسانی…") + (tunnelPort() > 0 ? L.t(" (از داخل تونل)") : "")).setCancelable(true).show();
        final Context app = a.getApplicationContext();
        new Thread(() -> {
            UpdCore.Info in = null;
            String err = null;
            try { in = fetchInfo(app); } catch (Exception e) { err = e.getMessage(); }
            final UpdCore.Info fin = in;
            final String ferr = err;
            new Handler(Looper.getMainLooper()).post(() -> {
                try { wait.dismiss(); } catch (Exception ignored) { }
                if (a.isFinishing()) return;
                if (fin == null) {
                    msg(a, L.t("بررسی به‌روزرسانی ناموفق بود"), L.t("فایل latest.json از GitHub دریافت نشد: ") + ferr
                            + L.t("\n\nاگر GitHub فیلتر است، اول VPN را وصل کنید و دوباره بزنید."));
                } else if (fin.versionCode <= ownCode(app)) {
                    msg(a, L.t("به‌روز هستید"), L.t("نسخهٔ نصب‌شده: ") + ownName(app) + L.t("\nآخرین نسخه: ") + fin.versionName);
                } else if (fin.minSdk > Build.VERSION.SDK_INT) {
                    msg(a, L.t("به‌روزرسانی"), L.t("نسخهٔ ") + fin.versionName + L.t(" به اندروید جدیدتری نیاز دارد."));
                } else offer(a, fin);
            });
        }, "o76-upd-check").start();
    }

    static void offer(final Activity a, final UpdCore.Info in) {
        String size = in.size > 0 ? Core.fmtBytes(in.size) : "?";
        new AlertDialog.Builder(a)
                .setTitle(L.t("نسخهٔ تازه: ") + in.versionName)
                .setMessage((in.notes.isEmpty() ? "" : in.notes + "\n\n") + L.t("فایل: ") + in.abi + " — " + size
                        + L.t("\nنسخهٔ نصب‌شده: ") + ownName(a))
                .setPositiveButton(L.t("دانلود و نصب"), (d, w) -> download(a, in))
                .setNegativeButton(L.t("بعداً"), null)
                .show();
    }

    static void download(final Activity a, final UpdCore.Info in) {
        if (busy) return;
        busy = true;
        final boolean[] cancel = {false};
        LinearLayout box = new LinearLayout(a);
        box.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * a.getResources().getDisplayMetrics().density);
        box.setPadding(pad, pad, pad, pad);
        final TextView tv = new TextView(a);
        tv.setText(L.t("دانلود…"));
        final ProgressBar pb = new ProgressBar(a, null, android.R.attr.progressBarStyleHorizontal);
        pb.setMax(1000);
        box.addView(tv);
        box.addView(pb, new LinearLayout.LayoutParams(-1, -2));
        final AlertDialog dlg = new AlertDialog.Builder(a).setTitle(L.t("به‌روزرسانی ") + in.versionName).setView(box)
                .setCancelable(false).setNegativeButton(L.t("لغو"), (d, w) -> cancel[0] = true).show();
        final Context app = a.getApplicationContext();
        final Handler h = new Handler(Looper.getMainLooper());
        new Thread(() -> {
            String err = null;
            File f = new File(apkDir(app), "076one-" + in.versionName.replaceAll("[^0-9A-Za-z._-]", "") + "-" + in.abi + ".apk");
            File part = new File(f.getPath() + ".part");
            try {
                init(app);
                boolean have = false;
                if (f.isFile()) {
                    try { have = UpdCore.sha256(f).equalsIgnoreCase(in.sha256); } catch (Exception ignored) { }
                    if (!have) //noinspection ResultOfMethodCallIgnored
                        f.delete();
                }
                if (!have) {
                    final long t0 = System.currentTimeMillis();
                    String route = viaBest(port -> {
                        try (FileOutputStream out = new FileOutputStream(part)) {
                            final String via = port > 0 ? L.t(" (از داخل تونل)") : L.t(" (مستقیم)");
                            UpdCore.download(in.url, port, out, in.size, (done, total) -> h.post(() -> {
                                if (total > 0) pb.setProgress((int) (done * 1000 / total));
                                long secs = Math.max(1, (System.currentTimeMillis() - t0) / 1000);
                                tv.setText(L.t("دانلود") + via + ": " + Core.fmtBytes(done) + (total > 0 ? " / " + Core.fmtBytes(total) : "")
                                        + " — " + Core.fmtBytes(done / secs) + "/s");
                            }), () -> cancel[0]);
                        }
                    });
                    Core.log(L.t("به‌روزرسانی: دانلود شد [") + route + "] " + part.length() + " bytes");
                    if (!part.renameTo(f)) throw new Exception("rename failed");
                }
                h.post(() -> tv.setText(L.t("بررسی SHA-256 و امضای فایل…")));
                UpdCore.verify(f, in, ownCerts(app));
                PackageInfo pi = app.getPackageManager().getPackageArchiveInfo(f.getPath(), 0);
                if (pi == null) throw new Exception(L.t("فایل APK خوانده نشد"));
                if (!app.getPackageName().equals(pi.packageName)) throw new SecurityException("package " + pi.packageName);
                //noinspection deprecation
                if (pi.versionCode != in.versionCode) throw new SecurityException("versionCode " + pi.versionCode + " ≠ " + in.versionCode);
                Core.log(L.t("به‌روزرسانی: SHA-256 و امضا درست است؛ باز کردن نصب‌کنندهٔ سیستم"));
                if (Build.VERSION.SDK_INT < 24) {
                    //noinspection ResultOfMethodCallIgnored
                    f.setReadable(true, false);
                }
            } catch (Exception e) {
                err = e.getMessage() == null ? e.toString() : e.getMessage();
                //noinspection ResultOfMethodCallIgnored
                part.delete();
                if (e instanceof SecurityException) //noinspection ResultOfMethodCallIgnored
                    f.delete();
            } finally {
                busy = false;
            }
            final String ferr = err;
            final File ff = f;
            h.post(() -> {
                try { dlg.dismiss(); } catch (Exception ignored) { }
                if (ferr != null) {
                    if (cancel[0]) { toast(a, L.t("لغو شد")); return; }
                    Core.log(L.t("به‌روزرسانی ناموفق: ") + ferr);
                    msg(a, L.t("به‌روزرسانی ناموفق"), ferr);
                    return;
                }
                install(a, ff);
            });
        }, "o76-upd-dl").start();
    }

    /** opens the system installer for a verified APK (asks for "install unknown apps" first on Android 8+) */
    static void install(final Activity a, final File f) {
        if (Build.VERSION.SDK_INT >= 26 && !a.getPackageManager().canRequestPackageInstalls()) {
            new AlertDialog.Builder(a).setTitle(L.t("اجازهٔ نصب"))
                    .setMessage(L.t("برای نصب نسخهٔ تازه، اجازهٔ «نصب برنامه‌های ناشناس» را به 076ONE بدهید، برگردید و دوباره «بررسی به‌روزرسانی» را بزنید (فایل دانلودشده دوباره استفاده می‌شود)."))
                    .setPositiveButton(L.t("باز کردن تنظیمات"), (d, w) -> {
                        try {
                            a.startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + a.getPackageName())));
                        } catch (Exception e) {
                            toast(a, e.getMessage());
                        }
                    })
                    .setNegativeButton(L.t("لغو"), null).show();
            return;
        }
        try {
            Intent i = new Intent(Intent.ACTION_VIEW);
            if (Build.VERSION.SDK_INT >= 24) {
                i.setDataAndType(ApkProvider.uri(f), MIME);
                i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            } else {
                i.setDataAndType(Uri.fromFile(f), MIME);
            }
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            a.startActivity(i);
        } catch (Exception e) {
            msg(a, L.t("به‌روزرسانی ناموفق"), L.t("نصب‌کنندهٔ سیستم باز نشد: ") + e.getMessage());
        }
    }

    static void msg(Activity a, String title, String m) {
        if (a.isFinishing()) return;
        new AlertDialog.Builder(a).setTitle(title).setMessage(m).setPositiveButton(L.t("بستن"), null).show();
    }

    static void toast(Activity a, String m) {
        android.widget.Toast.makeText(a, m, android.widget.Toast.LENGTH_LONG).show();
    }
}
