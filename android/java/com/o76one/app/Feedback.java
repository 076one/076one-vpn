package com.o76one.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.text.InputType;
import android.view.Gravity;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import java.net.URLEncoder;

/**
 * v1.8.6: in-app problem report. Builds a GitHub issue on the public repo
 * (076one/076one-vpn) prefilled with the user's description, device/network
 * info and the scrubbed log, and opens it in the browser. Nothing is sent by
 * the app itself; the user reviews and submits it on GitHub.
 */
final class Feedback {
    static final String REPO = "https://github.com/076one/076one-vpn";
    /** GitHub rejects very long /issues/new URLs; keep the encoded body under this */
    private static final int MAX_ENC = 6500;

    private Feedback() { }

    private static final String[] CATS = {
            "وصل نمی‌شود",
            "وصل می‌شود ولی سایت‌ها باز نمی‌شوند",
            "قطع و وصل می‌شود",
            "سرعت کم است",
            "برنامه بسته می‌شود / خطا می‌دهد",
            "پیشنهاد یا موارد دیگر"};

    static void show(final Activity a) {
        int p = (int) (16 * a.getResources().getDisplayMetrics().density);
        LinearLayout box = new LinearLayout(a);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(p, p / 2, p, 0);
        box.setLayoutDirection(L.dir());

        TextView hint = new TextView(a);
        hint.setText(L.t("نوع مشکل:"));
        box.addView(hint);
        final RadioGroup rg = new RadioGroup(a);
        for (int i = 0; i < CATS.length; i++) {
            RadioButton rb = new RadioButton(a);
            rb.setId(1000 + i);
            rb.setText(L.t(CATS[i]));
            rg.addView(rb);
        }
        rg.check(1000);
        box.addView(rg);

        final EditText et = new EditText(a);
        et.setHint(L.t("چه شد؟ کدام اپراتور/وای‌فای، از چه زمانی، کدام سایت یا برنامه…"));
        et.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        et.setMinLines(3);
        et.setGravity(Gravity.TOP | Gravity.START);
        box.addView(et);

        final CheckBox withLog = new CheckBox(a);
        withLog.setText(L.t("پیوست گزارش اتصال (بدون کلید، توکن و لینک کانفیگ)"));
        withLog.setChecked(true);
        box.addView(withLog);

        TextView warn = new TextView(a);
        warn.setTextSize(12);
        warn.setText(L.t("گزارش در صفحهٔ عمومی Issues گیت‌هاب ثبت می‌شود و همه می‌بینند؛ برای ثبت، حساب GitHub لازم است. پیش از ارسال همه‌چیز را می‌بینید."));
        box.addView(warn);

        android.widget.ScrollView sv = new android.widget.ScrollView(a);
        sv.addView(box);

        new AlertDialog.Builder(a)
                .setTitle(L.t("ارسال گزارش خطا"))
                .setView(sv)
                .setNegativeButton(L.t("بستن"), null)
                .setPositiveButton(L.t("پیش‌نمایش"), (d, w) -> {
                    int ci = Math.max(0, rg.getCheckedRadioButtonId() - 1000);
                    String desc = et.getText().toString().trim();
                    boolean log = withLog.isChecked();
                    new Thread(() -> {
                        final String full = body(a, CATS[ci], desc, log, 200);
                        a.runOnUiThread(() -> { if (!a.isFinishing()) preview(a, CATS[ci], desc, log, full); });
                    }, "o76-feedback").start();
                })
                .show();
    }

    private static void preview(final Activity a, final String cat, final String desc, final boolean log, final String full) {
        TextView tv = new TextView(a);
        int p = (int) (12 * a.getResources().getDisplayMetrics().density);
        tv.setPadding(p, p, p, p);
        tv.setTextSize(11);
        tv.setTextIsSelectable(true);
        tv.setTextDirection(android.view.View.TEXT_DIRECTION_LTR);
        tv.setText(full);
        android.widget.ScrollView sv = new android.widget.ScrollView(a);
        sv.addView(tv);
        new AlertDialog.Builder(a)
                .setTitle(L.t("پیش‌نمایش گزارش"))
                .setView(sv)
                .setNegativeButton(L.t("انصراف"), null)
                .setNeutralButton(L.t("فقط کپی"), (d, w) -> copy(a, full))
                .setPositiveButton(L.t("ثبت در GitHub"), (d, w) -> new Thread(() -> {
                    final String url = issueUrl(a, cat, desc, log, full);
                    a.runOnUiThread(() -> open(a, url));
                }, "o76-feedback").start())
                .show();
    }

    /** issue URL; if the log does not fit, fewer lines go in the URL and the full report is copied for pasting */
    static String issueUrl(Context c, String cat, String desc, boolean log, String full) {
        String title = "[" + ver(c) + "] " + cat + (desc.isEmpty() ? "" : " — " + oneLine(desc, 60));
        String b = full;
        boolean cut = false;
        int lines = 200;
        while (enc(b).length() > MAX_ENC && lines > 0) {
            lines = lines > 40 ? lines - 20 : lines - 5;
            b = body(c, cat, desc, log, Math.max(lines, 0));
            cut = true;
        }
        if (cut) {
            ((Activity) c).runOnUiThread(() -> copy(c, full));
            b = b + "\n\n> " + "Full log was cut to fit; the complete report is on the reporter's clipboard — paste it in a comment if asked.";
        }
        return REPO + "/issues/new?title=" + enc(title) + "&body=" + enc(b);
    }

    static String body(Context c, String cat, String desc, boolean withLog, int lines) {
        StringBuilder sb = new StringBuilder();
        sb.append("**Problem:** ").append(cat).append('\n');
        sb.append("**Description:**\n").append(desc.isEmpty() ? "-" : desc).append("\n\n");
        sb.append("| | |\n|---|---|\n");
        sb.append("| App | ").append(ver(c)).append(" |\n");
        sb.append("| Mode | ").append(safe(() -> Core.modeLabel(Core.mode(c)))).append(" |\n");
        sb.append("| Android | ").append(Build.VERSION.RELEASE).append(" (API ").append(Build.VERSION.SDK_INT).append(") |\n");
        sb.append("| Device | ").append(Build.MANUFACTURER).append(' ').append(Build.MODEL).append(" |\n");
        sb.append("| ABI | ").append(Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "?").append(" |\n");
        sb.append("| Network | ").append(net(c)).append(" |\n");
        if (withLog && lines > 0) {
            String lg = Core.scrub(O76App.tail(lines), c);
            sb.append("\n<details><summary>Log — last ").append(lines).append(" lines</summary>\n\n```\n")
                    .append(lg.replace("```", "'''")).append("\n```\n</details>\n");
        }
        return sb.toString();
    }

    private static String net(Context c) {
        try {
            ConnectivityManager cm = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
            String t = "?";
            if (Build.VERSION.SDK_INT >= 23 && cm != null) {
                // the active network is usually our VPN; look at the underlying transports
                for (android.net.Network n : cm.getAllNetworks()) {
                    NetworkCapabilities nc = cm.getNetworkCapabilities(n);
                    if (nc == null || nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                    if (nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) { t = "Wi-Fi"; break; }
                    if (nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) t = "Mobile";
                }
            }
            if ("Mobile".equals(t)) {
                TelephonyManager tm = (TelephonyManager) c.getSystemService(Context.TELEPHONY_SERVICE);
                String op = tm == null ? "" : tm.getNetworkOperatorName();
                if (op != null && !op.isEmpty()) t += " · " + op;
            }
            return t;
        } catch (Throwable e) {
            return "?";
        }
    }

    private interface S { String get() throws Exception; }

    private static String safe(S s) {
        try { String v = s.get(); return v == null ? "?" : v; } catch (Throwable t) { return "?"; }
    }

    private static String ver(Context c) {
        try {
            android.content.pm.PackageInfo pi = c.getPackageManager().getPackageInfo(c.getPackageName(), 0);
            return "v" + pi.versionName;
        } catch (Exception e) { return "v?"; }
    }

    private static String oneLine(String s, int max) {
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() > max ? s.substring(0, max) + "…" : s;
    }

    private static String enc(String s) {
        try { return URLEncoder.encode(s, "UTF-8").replace("+", "%20"); } catch (Exception e) { return ""; }
    }

    private static void copy(Context c, String s) {
        try {
            ClipboardManager cm = (ClipboardManager) c.getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("076one report", s));
            Toast.makeText(c, L.t("گزارش کامل کپی شد"), Toast.LENGTH_SHORT).show();
        } catch (Throwable ignored) { }
    }

    private static void open(Activity a, String url) {
        try {
            Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            a.startActivity(i);
        } catch (Throwable t) {
            copy(a, url);
            Toast.makeText(a, L.t("مرورگری پیدا نشد؛ لینک کپی شد."), Toast.LENGTH_LONG).show();
        }
    }
}
