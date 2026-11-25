package com.o76one.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Settings: editable SNI list (add / remove / import one-per-line / reset) and HTTP/2-only switch. Persian RTL. */
public class SettingsActivity extends Activity {
    private static final int ACCENT = Color.rgb(91, 33, 182);
    private LinearLayout listBox;
    private EditText addEt;
    private boolean changed;

    private int dp(float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, getResources().getDisplayMetrics());
    }

    private TextView text(String s, float sp, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(Color.rgb(30, 30, 30));
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setPadding(0, dp(4), 0, dp(4));
        return t;
    }

    private Button button(String s, int color) {
        return button(s, color, 0);
    }

    private Button button(String s, int color, int icon) {
        return MainActivity.Ui.button(this, s, icon, color);
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(Color.rgb(245, 247, 250));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(16), dp(16), dp(24));
        root.setLayoutDirection(L.dir());
        root.setTextDirection(L.tdir());
        sv.addView(root);

        TextView title = text(L.t("تنظیمات"), 24, true);
        title.setGravity(Gravity.CENTER);
        title.setTextColor(ACCENT);
        root.addView(title, new LinearLayout.LayoutParams(-1, -2));

        // ---- one switch: best settings (default) ----
        CheckBox best = new CheckBox(this);
        best.setText(L.t("بهترین تنظیمات برای عبور از فیلترینگ (پیشنهادی)"));
        best.setTypeface(Typeface.DEFAULT_BOLD);
        best.setTextSize(16);
        best.setChecked(Core.bestMode(this));
        root.addView(best);
        root.addView(text(L.t("تکه‌تکه کردن ClientHello (رکورد TLS + بسته‌های TCP کوچک ۱۰ تا ۵۰ بایت با فاصلهٔ ۱ تا ۵ میلی‌ثانیه)، ")
                + L.t("اثر انگشت TLS مرورگر Chrome، MTU تونل 1280، MSS اتصال 1300، تشخیص سریع قطعی (HTTP/2 PING)، ")
                + L.t("چرخش خودکار SNI و پورت، و تعویض خودکار سرور اگر ۸ ثانیه داده‌ای برنگردد."), 12, false));

        final LinearLayout adv = new LinearLayout(this);
        adv.setOrientation(LinearLayout.VERTICAL);
        adv.setPadding(dp(8), dp(4), dp(8), dp(8));
        GradientDrawable ag = new GradientDrawable();
        ag.setColor(Color.WHITE);
        ag.setCornerRadius(dp(10));
        ag.setStroke(dp(1), Color.rgb(203, 213, 225));
        adv.setBackground(ag);
        root.addView(adv, new LinearLayout.LayoutParams(-1, -2));
        buildAdvanced(adv);
        adv.setVisibility(Core.bestMode(this) ? View.GONE : View.VISIBLE);
        best.setOnCheckedChangeListener((v, on) -> {
            Core.prefs(this).edit().putBoolean("best", on).apply();
            adv.setVisibility(on ? View.GONE : View.VISIBLE);
            changed = true;
        });

        root.addView(text(L.t("فهرست SNI"), 17, true));
        root.addView(text(L.t("اسکنر SNIها را به‌صورت چرخشی روی سرورها و پورت‌ها پخش می‌کند، سپس ترکیب‌های مختلف را با «تست واقعی» ")
                + L.t("(عبور داده از تونل) می‌سنجد و آن‌هایی که واقعاً کار می‌کنند اول می‌آیند. سرور MASQUE کلادفلر هر SNI را می‌پذیرد."), 13, false));

        listBox = new LinearLayout(this);
        listBox.setOrientation(LinearLayout.VERTICAL);
        root.addView(listBox, new LinearLayout.LayoutParams(-1, -2));

        addEt = new EditText(this);
        addEt.setSingleLine(true);
        addEt.setHint("example.com");
        addEt.setTextDirection(View.TEXT_DIRECTION_LTR);
        addEt.setTextSize(14);
        Button addBtn = button(L.t("افزودن"), ACCENT, R.drawable.ic_check);
        LinearLayout addRow = new LinearLayout(this);
        addRow.setOrientation(LinearLayout.HORIZONTAL);
        addRow.setBaselineAligned(false);
        addRow.setGravity(Gravity.CENTER_VERTICAL);
        addRow.addView(addEt, new LinearLayout.LayoutParams(0, -2, 1f));
        LinearLayout.LayoutParams alp = new LinearLayout.LayoutParams(dp(112), dp(MainActivity.Ui.ROW_H));
        alp.setMargins(dp(MainActivity.Ui.MARGIN), dp(MainActivity.Ui.MARGIN), dp(MainActivity.Ui.MARGIN), dp(MainActivity.Ui.MARGIN));
        addRow.addView(addBtn, alp);
        root.addView(addRow, new LinearLayout.LayoutParams(-1, -2));
        addBtn.setOnClickListener(v -> {
            List<String> add = Core.parseSnis(addEt.getText().toString());
            if (add.isEmpty()) {
                Toast.makeText(this, L.t("SNI نامعتبر است"), Toast.LENGTH_SHORT).show();
                return;
            }
            List<String> l = Core.snis(this);
            for (String s : add) if (!l.contains(s)) l.add(s);
            Core.saveSnis(this, l);
            addEt.setText("");
            changed = true;
            render();
        });

        Button importBtn = button(L.t("وارد کردن از متن"), ACCENT, R.drawable.ic_paste);
        Button resetBtn = button(L.t("بازگردانی پیش‌فرض"), Color.rgb(100, 116, 139), R.drawable.ic_refresh);
        root.addView(MainActivity.Ui.row(this, importBtn, resetBtn));
        importBtn.setOnClickListener(v -> showImport());
        resetBtn.setOnClickListener(v -> {
            Core.saveSnis(this, new ArrayList<>(Arrays.asList(Core.DEFAULT_SNIS)));
            changed = true;
            render();
        });

        Button scanBtn = button(L.t("ذخیره و اسکن دوباره"), Color.rgb(14, 116, 144), R.drawable.ic_search);
        LinearLayout sr = MainActivity.Ui.row(this, scanBtn);
        sr.setPadding(0, dp(12), 0, 0);
        root.addView(sr);
        scanBtn.setOnClickListener(v -> {
            if (Core.hasConfig(this)) {
                Servers.startScan(this);
                Toast.makeText(this, L.t("اسکن در پس‌زمینه شروع شد"), Toast.LENGTH_SHORT).show();
            }
            changed = false;
            finish();
        });

        // ---- v1.8.5 Update ----
        root.addView(text(L.t("به‌روزرسانی"), 17, true));
        root.addView(text(L.t("نسخهٔ تازه از مخزن عمومی GitHub (076one/076one-vpn) دریافت می‌شود؛ وقتی VPN وصل است از داخل تونل خود برنامه. ")
                + L.t("پیش از نصب، SHA-256 و امضای فایل با امضای همین برنامه مقایسه می‌شود."), 13, false));
        Button updBtn = button(L.t("بررسی به‌روزرسانی"), ACCENT, R.drawable.ic_download);
        updBtn.setOnClickListener(v -> Updater.check(this));
        root.addView(MainActivity.Ui.row(this, updBtn));
        android.widget.CheckBox updAuto = new android.widget.CheckBox(this);
        updAuto.setText(L.t("بررسی خودکار روزی یک بار هنگام باز شدن برنامه"));
        updAuto.setChecked(Updater.autoCheck(this));
        updAuto.setOnCheckedChangeListener((cb, on) -> Updater.setAutoCheck(this, on));
        root.addView(updAuto);

        // ---- v1.8.6 Feedback ----
        root.addView(text(L.t("گزارش خطا و بازخورد"), 17, true));
        root.addView(text(L.t("اگر وصل نمی‌شود یا مشکلی دارد، توضیح بدهید؛ گزارش اتصال (بدون کلید و توکن) پیوست می‌شود تا خطا را پیدا و رفع کنیم."), 13, false));
        Button fbBtn = button(L.t("ارسال گزارش خطا"), ACCENT, R.drawable.ic_share);
        fbBtn.setOnClickListener(v -> Feedback.show(this));
        root.addView(MainActivity.Ui.row(this, fbBtn));

        // ---- v1.6 About ----
        root.addView(text(L.t("درباره"), 17, true));
        String ver = "";
        try { ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName; } catch (Exception ignored) { }
        root.addView(text(L.t("076one نسخهٔ ") + ver + L.t(" — هستهٔ o76core بر پایهٔ usque (MIT)."), 13, false));
        TextView ae = text(L.t("حالت Aether از هستهٔ Aether v") + Aether.VERSION + L.t(" ساختهٔ CluvexStudio استفاده می‌کند (مجوز AGPL-3.0، بدون تغییر، ")
                + L.t("فقط arm64): ") + Aether.REPO + L.t(" — کد منبع همین نسخه: ") + Aether.REPO + "/tree/v" + Aether.VERSION, 13, false);
        ae.setTextIsSelectable(true);
        root.addView(ae);
        TextView fx = text(L.t("حالت Firefox از هستهٔ Predator VPN v") + Fox.VERSION + L.t(" (erfan-tahvilian) استفاده می‌کند (مجوز GPL-3.0، بدون تغییر): ")
                + Fox.REPO + L.t(" — وابسته به موزیلا نیست؛ فقط با حساب خود شما وارد می‌شود."), 13, false);
        fx.setTextIsSelectable(true);
        root.addView(fx);
        root.addView(text(L.t("حالت وارپ+ از هستهٔ warp-plus ") + WarpPlus.VERSION + L.t(" (bepass-org، MIT) با سایفون (psiphon-tunnel-core، GPL-3.0) ")
                + L.t("استفاده می‌کند؛ کل libwplus.so تحت GPL-3.0 است و منبع و تغییرات در «مجوزها» آمده: ") + WarpPlus.REPO, 13, false));
        TextView ch = text(L.t("حالت «کانفیگ + سایفون» از Xray-core ") + Chain.XRAY_VERSION + L.t(" (XTLS، مجوز MPL-2.0، بدون تغییر) و سایفون (psiphon-tunnel-core، GPL-3.0) ")
                + L.t("در یک فایل libchain.so استفاده می‌کند که کل آن تحت GPL-3.0 است؛ منبع: ") + Chain.XRAY_REPO + "/tree/" + Chain.XRAY_VERSION, 13, false);
        ch.setTextIsSelectable(true);
        root.addView(ch);
        Button licBtn = button(L.t("مجوزها و اطلاعیه‌ها"), Color.rgb(100, 116, 139), R.drawable.ic_file);
        licBtn.setOnClickListener(v -> showAsset());
        root.addView(MainActivity.Ui.row(this, licBtn));

        setContentView(sv);
        render();
    }

    /** v1.6: license texts shipped in assets/licenses (Aether AGPL-3.0, its third-party notices, our notice) */
    private void showAsset() {
        final String[] files = {"licenses/NOTICE-aether.txt", "licenses/aether-LICENSE.txt", "licenses/aether-THIRD-PARTY-NOTICES.txt",
                "licenses/NOTICE-firefox.txt", "licenses/predator-LICENSE.txt", "licenses/firefox-mode-libfpn-main.go.txt", "licenses/Cinzel-OFL.txt", "licenses/NOTICE-wplus.txt", "licenses/warp-plus-LICENSE.txt", "licenses/psiphon-LICENSE.txt",
                "licenses/NOTICE-chain.txt", "licenses/xray-core-LICENSE.txt", "licenses/qpack-LICENSE.txt", "licenses/tailscale-netlink-LICENSE.txt"};
        final String[] names = {L.t("اطلاعیهٔ Aether در 076one"), L.t("مجوز Aether (AGPL-3.0)"), L.t("اطلاعیه‌های شخص ثالث Aether"),
                L.t("اطلاعیهٔ حالت Firefox"), L.t("مجوز Predator VPN (GPL-3.0)"), L.t("منبع libfpn (main.go)"), L.t("فونت Cinzel (SIL OFL 1.1)"), L.t("اطلاعیهٔ حالت وارپ+ (منبع و تغییرات)"), L.t("مجوز warp-plus (MIT)"), L.t("مجوز سایفون (GPL-3.0)"),
                L.t("اطلاعیهٔ حالت کانفیگ + سایفون (منبع و تغییرات)"), L.t("مجوز Xray-core (MPL-2.0)"), "qpack (MIT)", "tailscale/netlink (Apache-2.0)"};
        new AlertDialog.Builder(this).setTitle(L.t("مجوزها")).setItems(names, (d, w) -> {
            String t;
            try (java.io.InputStream in = getAssets().open(files[w])) {
                java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0 && bo.size() < 150_000) bo.write(buf, 0, n);
                t = bo.toString("UTF-8");
                if (bo.size() >= 150_000) t += L.t("\n\n… (کوتاه شده؛ متن کامل در فایل APK: assets/") + files[w] + ")";
            } catch (Exception e) {
                t = "—" + e.getMessage();
            }
            TextView tv = new TextView(this);
            tv.setText(t);
            tv.setTextSize(11);
            tv.setTextIsSelectable(true);
            tv.setTextDirection(View.TEXT_DIRECTION_LTR);
            tv.setPadding(dp(16), dp(8), dp(16), dp(8));
            ScrollView s2 = new ScrollView(this);
            s2.addView(tv);
            new AlertDialog.Builder(this).setTitle(names[w]).setView(s2).setPositiveButton(L.t("بستن"), null).show();
        }).setNegativeButton(L.t("بستن"), null).show();
    }

    private LinearLayout.LayoutParams wrap() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, dp(MainActivity.Ui.ROW_H));
        lp.setMargins(dp(MainActivity.Ui.MARGIN), dp(MainActivity.Ui.MARGIN), dp(MainActivity.Ui.MARGIN), dp(MainActivity.Ui.MARGIN));
        return lp;
    }

    /** A row of choice buttons; the selected one is highlighted. */
    private void choices(LinearLayout parent, String title, final String[] values, final String[] labels, String current,
                         final Core.Fn<String> onPick) {
        parent.addView(text(title, 14, true));
        final LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setBaselineAligned(false);
        android.widget.HorizontalScrollView hs = new android.widget.HorizontalScrollView(this);
        hs.addView(row);
        parent.addView(hs);
        final MainActivity.Ui.IconBtn[] bs = new MainActivity.Ui.IconBtn[values.length];
        for (int i = 0; i < values.length; i++) {
            final int k = i;
            bs[i] = MainActivity.Ui.choiceButton(this, labels[i], 0, ACCENT, values[i].equals(current));
            bs[i].setOnClickListener(v -> {
                for (int j = 0; j < bs.length; j++) MainActivity.Ui.styleChoice(bs[j], ACCENT, j == k);
                onPick.accept(values[k]);
                changed = true;
            });
            row.addView(bs[i], wrap());
        }
    }

    private EditText field(LinearLayout parent, String title, String value, final String key, final boolean isInt) {
        parent.addView(text(title, 14, true));
        final EditText et = new EditText(this);
        et.setSingleLine(true);
        et.setText(value);
        et.setTextDirection(View.TEXT_DIRECTION_LTR);
        et.setTextSize(14);
        et.addTextChangedListener(new android.text.TextWatcher() {
            public void beforeTextChanged(CharSequence a, int b, int c, int d) { }
            public void onTextChanged(CharSequence a, int b, int c, int d) { }
            public void afterTextChanged(android.text.Editable e) {
                String v = e.toString().trim();
                if (isInt) {
                    try { Core.prefs(SettingsActivity.this).edit().putInt(key, Integer.parseInt(v)).apply(); } catch (Exception ignored) { }
                } else {
                    Core.prefs(SettingsActivity.this).edit().putString(key, v).apply();
                }
                changed = true;
            }
        });
        parent.addView(et, new LinearLayout.LayoutParams(-1, -2));
        return et;
    }

    private void buildAdvanced(LinearLayout adv) {
        android.content.SharedPreferences p = Core.prefs(this);
        adv.addView(text(L.t("تنظیمات دستی"), 16, true));
        choices(adv, L.t("تکه‌تکه کردن ClientHello (HTTP/2)"), new String[]{"both", "tlsrec", "tcp", "off"},
                new String[]{L.t("رکورد TLS + TCP"), L.t("فقط رکورد TLS"), L.t("فقط TCP"), L.t("خاموش")}, p.getString("frag", Core.BEST_FRAG),
                v -> p.edit().putString("frag", v).apply());
        field(adv, L.t("اندازهٔ تکه‌ها (بایت، بازه 1-100)، مثل 10-50"), p.getString("fragsize", Core.BEST_FRAGSIZE), "fragsize", false);
        field(adv, L.t("فاصلهٔ بین تکه‌های TCP (میلی‌ثانیه، بازه 0-10)، مثل 1-5"), p.getString("fragdelay", Core.BEST_FRAGDELAY), "fragdelay", false);
        choices(adv, L.t("اثر انگشت TLS"), new String[]{"chrome", "go"}, new String[]{"Chrome", L.t("Go (پیش‌فرض usque)")},
                p.getString("fp", Core.BEST_FP), v -> p.edit().putString("fp", v).apply());
        choices(adv, L.t("MTU تونل"), new String[]{"1280", "1260", "1240", "1220", "1200"},
                new String[]{"1280", "1260", "1240", "1220", "1200"}, String.valueOf(p.getInt("mtu", Core.BEST_MTU)),
                v -> p.edit().putInt("mtu", Integer.parseInt(v)).apply());
        adv.addView(text(L.t("زیر 1280، IPv6 داخل تونل خاموش می‌شود."), 12, false));
        field(adv, L.t("MSS اتصال TCP به سرور (0 = پیش‌فرض سیستم)"), String.valueOf(p.getInt("mss", Core.BEST_MSS)), "mss", true);
        CheckBox nd = new CheckBox(this);
        nd.setText(L.t("TCP_NODELAY پس از هندشیک"));
        nd.setChecked(p.getBoolean("nodelay", true));
        nd.setOnCheckedChangeListener((v, on) -> { p.edit().putBoolean("nodelay", on).apply(); changed = true; });
        adv.addView(nd);
        field(adv, L.t("پورت‌های اسکن (با کاما)"), Core.ports(this), "ports", false);
        CheckBox h2 = new CheckBox(this);
        h2.setText(L.t("فقط HTTP/2 (QUIC/HTTP/3 استفاده نشود)"));
        h2.setChecked(Core.h2Only(this));
        h2.setOnCheckedChangeListener((v, on) -> {
            Core.prefs(this).edit().putBoolean("h2only", on).apply();
            changed = true;
        });
        adv.addView(h2);
    }

    private void render() {
        listBox.removeAllViews();
        final List<String> l = Core.snis(this);
        for (int i = 0; i < l.size(); i++) {
            final String s = l.get(i);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dp(10), dp(4), dp(10), dp(4));
            GradientDrawable g = new GradientDrawable();
            g.setColor(Color.WHITE);
            g.setCornerRadius(dp(8));
            g.setStroke(dp(1), Color.rgb(203, 213, 225));
            row.setBackground(g);
            TextView t = new TextView(this);
            t.setText((i + 1) + ". " + s);
            t.setTextDirection(View.TEXT_DIRECTION_LTR);
            t.setTextSize(14);
            t.setTextColor(Color.rgb(30, 30, 30));
            row.addView(t, new LinearLayout.LayoutParams(0, -2, 1f));
            android.widget.ImageButton del = MainActivity.Ui.iconButton(this, R.drawable.ic_delete, Color.rgb(185, 28, 28), L.t("حذف"), v -> {
                List<String> cur = Core.snis(this);
                if (cur.size() <= 1) {
                    Toast.makeText(this, L.t("حداقل یک SNI لازم است"), Toast.LENGTH_SHORT).show();
                    return;
                }
                cur.remove(s);
                Core.saveSnis(this, cur);
                changed = true;
                render();
            });
            row.addView(del);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
            lp.setMargins(0, dp(3), 0, dp(3));
            listBox.addView(row, lp);
        }
    }

    private void showImport() {
        final EditText et = new EditText(this);
        et.setHint("sni1.example.com\nsni2.example.com");
        et.setMinLines(5);
        et.setTextSize(13);
        et.setTextDirection(View.TEXT_DIRECTION_LTR);
        new AlertDialog.Builder(this).setTitle(L.t("وارد کردن SNI"))
                .setMessage(L.t("هر خط یک SNI. موارد تکراری و نامعتبر نادیده گرفته می‌شوند."))
                .setView(et)
                .setPositiveButton(L.t("افزودن به فهرست"), (d, w) -> importText(et.getText().toString(), false))
                .setNeutralButton(L.t("جایگزینی فهرست"), (d, w) -> importText(et.getText().toString(), true))
                .setNegativeButton(L.t("لغو"), null).show();
    }

    private void importText(String txt, boolean replace) {
        List<String> add = Core.parseSnis(txt);
        if (add.isEmpty()) {
            Toast.makeText(this, L.t("SNI معتبری پیدا نشد"), Toast.LENGTH_SHORT).show();
            return;
        }
        List<String> l = replace ? new ArrayList<>() : Core.snis(this);
        int n = 0;
        for (String s : add) if (!l.contains(s)) { l.add(s); n++; }
        Core.saveSnis(this, l);
        changed = true;
        Toast.makeText(this, n + L.t(" SNI اضافه شد"), Toast.LENGTH_SHORT).show();
        render();
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (changed) Core.log(L.t("تنظیمات تغییر کرد — برای اعمال SNI جدید، دوباره اسکن کنید"));
        changed = false;
    }
}
