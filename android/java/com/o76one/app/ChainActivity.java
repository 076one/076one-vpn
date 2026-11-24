package com.o76one.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.util.List;

/**
 * v1.8.2 «کانفیگ + سایفون» (Config + Psiphon) screen: the user's own proxy links (paste, clipboard, subscription),
 * a real connectivity / latency test of each, which one is used (tap), the Psiphon layer switch and its exit country.
 */
public class ChainActivity extends Activity {
    private static final int ACCENT = Color.rgb(14, 116, 144);
    private final Handler ui = new Handler(Looper.getMainLooper());
    private LinearLayout listBox, regionBox;
    private TextView statusTv;
    private EditText subEt;
    private Button testBtn;
    private volatile boolean busy;
    private String sig = "";

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

    private LinearLayout.LayoutParams wrap() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, dp(MainActivity.Ui.ROW_H));
        lp.setMargins(dp(MainActivity.Ui.MARGIN), dp(MainActivity.Ui.MARGIN), dp(MainActivity.Ui.MARGIN), dp(MainActivity.Ui.MARGIN));
        return lp;
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

        TextView title = text(L.t("کانفیگ + سایفون"), 24, true);
        title.setGravity(Gravity.CENTER);
        title.setTextColor(ACCENT);
        root.addView(title, new LinearLayout.LayoutParams(-1, -2));
        root.addView(text(L.t("کانفیگ‌های خودتان (vless با Reality / ws / grpc / tcp، vmess، trojan، shadowsocks) را بچسبانید. ")
                + L.t("076one کانفیگ انتخاب‌شده را با Xray-core اجرا می‌کند و سایفون را از داخل آن وصل می‌کند: ")
                + L.t("گوشی ← کانفیگ شما ← سایفون ← اینترنت. با خاموش کردن «لایهٔ سایفون» فقط خود کانفیگ استفاده می‌شود. ")
                + L.t("کانفیگ‌ها فقط روی همین گوشی ذخیره می‌شوند."), 13, false));

        Button paste = MainActivity.Ui.button(this, L.t("چسباندن از کلیپ‌بورد"), R.drawable.ic_paste, ACCENT);
        paste.setOnClickListener(v -> pasteClipboard());
        Button manual = MainActivity.Ui.button(this, L.t("افزودن دستی"), R.drawable.ic_link, ACCENT);
        manual.setOnClickListener(v -> addManual());
        root.addView(MainActivity.Ui.row(this, paste, manual));

        root.addView(text(L.t("لینک اشتراک (اختیاری)"), 17, true));
        subEt = new EditText(this);
        subEt.setHint("https://…");
        subEt.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        subEt.setSingleLine(true);
        subEt.setTextDirection(View.TEXT_DIRECTION_LTR);
        subEt.setText(Chain.subUrl(this));
        root.addView(subEt, new LinearLayout.LayoutParams(-1, -2));
        Button subBtn = MainActivity.Ui.button(this, L.t("دریافت از اشتراک"), R.drawable.ic_download, ACCENT);
        subBtn.setOnClickListener(v -> fetchSub());
        root.addView(MainActivity.Ui.row(this, subBtn));

        CheckBox psi = new CheckBox(this);
        psi.setText(L.t("لایهٔ سایفون (پیشنهادی)"));
        psi.setTypeface(Typeface.DEFAULT_BOLD);
        psi.setTextSize(15);
        psi.setChecked(Chain.psiphon(this));
        psi.setOnCheckedChangeListener((v, on) -> {
            Chain.setPsiphon(this, on);
            regionBox.setVisibility(on ? View.VISIBLE : View.GONE);
        });
        root.addView(psi);
        root.addView(text(L.t("روشن: سایفون از داخل کانفیگ وصل می‌شود (خروجی در کشور انتخابی، پایدارتر در برابر فیلترینگ). ")
                + L.t("خاموش: ترافیک مستقیم از کانفیگ بیرون می‌رود (سریع‌تر)."), 12, false));

        // v1.8.3: optional last resort when every config fails with Psiphon on
        CheckBox noPsiFb = new CheckBox(this);
        noPsiFb.setText(L.t("جایگزین خودکار بدون سایفون"));
        noPsiFb.setTextSize(14);
        noPsiFb.setChecked(Chain.noPsiFallback(this));
        noPsiFb.setOnCheckedChangeListener((v, on) -> Chain.setNoPsiFallback(this, on));
        root.addView(noPsiFb);
        root.addView(text(L.t("اگر همهٔ کانفیگ‌ها با سایفون وصل نشدند، بهترین کانفیگ بدون سایفون امتحان می‌شود (پیش‌فرض خاموش). ")
                + L.t("برنامه هیچ‌وقت تسلیم نمی‌شود: پس از دو بازیابی ناموفق، کانفیگ سالم بعدی (کمترین تأخیر) خودکار انتخاب می‌شود."), 12, false));

        regionBox = new LinearLayout(this);
        regionBox.setOrientation(LinearLayout.VERTICAL);
        regionBox.addView(text(L.t("کشور خروجی سایفون"), 17, true));
        LinearLayout rr = new LinearLayout(this);
        rr.setOrientation(LinearLayout.HORIZONTAL);
        HorizontalScrollView hs = new HorizontalScrollView(this);
        hs.addView(rr);
        regionBox.addView(hs);
        final MainActivity.Ui.IconBtn[] bs = new MainActivity.Ui.IconBtn[Chain.REGIONS.length];
        String cur = Chain.region(this);
        for (int i = 0; i < Chain.REGIONS.length; i++) {
            final int k = i;
            bs[i] = MainActivity.Ui.choiceButton(this, Chain.regionLabel(Chain.REGIONS[i]), 0, ACCENT, Chain.REGIONS[i].equals(cur));
            bs[i].setOnClickListener(v -> {
                for (int j = 0; j < bs.length; j++) MainActivity.Ui.styleChoice(bs[j], ACCENT, j == k);
                Chain.setRegion(this, Chain.REGIONS[k]);
            });
            rr.addView(bs[i], wrap());
        }
        regionBox.setVisibility(Chain.psiphon(this) ? View.VISIBLE : View.GONE);
        root.addView(regionBox, new LinearLayout.LayoutParams(-1, -2));

        testBtn = MainActivity.Ui.button(this, L.t("تست همه"), R.drawable.ic_speed, ACCENT);
        testBtn.setOnClickListener(v -> testAll());
        Button clr = MainActivity.Ui.button(this, L.t("پاک کردن همه"), R.drawable.ic_delete, Color.rgb(100, 116, 139));
        clr.setOnClickListener(v -> new AlertDialog.Builder(this).setTitle(L.t("پاک کردن همهٔ کانفیگ‌ها؟"))
                .setPositiveButton(L.t("پاک کن"), (d, w) -> { Chain.clear(this); render(); })
                .setNegativeButton(L.t("لغو"), null).show());
        root.addView(MainActivity.Ui.row(this, testBtn, clr));
        statusTv = text("", 13, false);
        root.addView(statusTv);

        root.addView(text(L.t("کانفیگ‌ها (لمس = انتخاب، لمس طولانی = حذف):"), 15, true));
        listBox = new LinearLayout(this);
        listBox.setOrientation(LinearLayout.VERTICAL);
        root.addView(listBox, new LinearLayout.LayoutParams(-1, -2));

        Button use = MainActivity.Ui.button(this, L.t("استفاده از حالت کانفیگ + سایفون"), R.drawable.ic_check, ACCENT);
        use.setOnClickListener(v -> {
            if (!Chain.configured(this)) {
                Toast.makeText(this, L.t("اول یک کانفیگ اضافه کنید"), Toast.LENGTH_LONG).show();
                return;
            }
            Core.setMode(this, Core.MODE_CHAIN);
            Core.log(L.t("حالت اتصال: کانفیگ + سایفون — ") + Chain.describe(this));
            boolean active = O76VpnService.state == O76VpnService.ST_ON || O76VpnService.state == O76VpnService.ST_CONNECTING
                    || O76VpnService.state == O76VpnService.ST_RECONNECTING;
            Toast.makeText(this, active ? L.t("حالت کانفیگ + سایفون — برای اعمال، یک بار قطع و وصل کنید") : L.t("حالت کانفیگ + سایفون انتخاب شد"), Toast.LENGTH_LONG).show();
            finish();
        });
        root.addView(MainActivity.Ui.row(this, use));

        TextView lic = text(L.t("هسته‌ها: Xray-core ") + Chain.XRAY_VERSION + L.t(" (XTLS، مجوز MPL-2.0) — ") + Chain.XRAY_REPO
                + L.t("\nسایفون: psiphon-tunnel-core (Psiphon Inc.، مجوز GPL-3.0). کل libchain.so تحت GPL-3.0 است؛ متن مجوزها در تنظیمات ← مجوزها."), 12, false);
        lic.setTextColor(Color.rgb(100, 116, 139));
        root.addView(lic);
        setContentView(sv);
        render();
        tick.run();
    }

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            statusTv.setText(Chain.testing ? Chain.testStatus : busy ? L.t("در حال کار…") : Chain.testStatus);
            testBtn.setEnabled(!Chain.testing && !busy);
            String s = Chain.testing + "|" + Chain.list(ChainActivity.this).size() + "|" + Chain.selected(ChainActivity.this) + "|" + Chain.testStatus;
            if (!s.equals(sig)) render();
            ui.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onDestroy() {
        ui.removeCallbacks(tick);
        super.onDestroy();
    }

    private void addLinks(String text) {
        List<String> ls = Chain.extract(text);
        if (ls.isEmpty()) {
            Toast.makeText(this, L.t("لینک vless / vmess / trojan / ss پیدا نشد"), Toast.LENGTH_LONG).show();
            return;
        }
        int n = Chain.add(this, ls);
        Toast.makeText(this, n + L.t(" کانفیگ تازه اضافه شد") + (ls.size() > n ? " (" + (ls.size() - n) + L.t(" تکراری)") : ""), Toast.LENGTH_LONG).show();
        Core.log(L.t("کانفیگ + سایفون: ") + n + L.t(" کانفیگ تازه اضافه شد"));
        render();
        if (n > 0) testAll();
    }

    private void pasteClipboard() {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData cd = cm == null ? null : cm.getPrimaryClip();
            StringBuilder sb = new StringBuilder();
            if (cd != null) for (int i = 0; i < cd.getItemCount(); i++) {
                CharSequence t = cd.getItemAt(i).coerceToText(this);
                if (t != null) sb.append(t).append('\n');
            }
            if (sb.length() == 0) {
                Toast.makeText(this, L.t("کلیپ‌بورد خالی است"), Toast.LENGTH_LONG).show();
                return;
            }
            addLinks(sb.toString());
        } catch (Exception e) {
            Toast.makeText(this, L.t("خطا: ") + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void addManual() {
        final EditText et = new EditText(this);
        et.setHint("vless://…  vmess://…  trojan://…  ss://…");
        et.setMinLines(4);
        et.setTextSize(12);
        et.setTextDirection(View.TEXT_DIRECTION_LTR);
        new AlertDialog.Builder(this).setTitle(L.t("افزودن کانفیگ (هر خط یکی)"))
                .setView(et)
                .setPositiveButton(L.t("افزودن و تست"), (d, w) -> addLinks(et.getText().toString()))
                .setNegativeButton(L.t("لغو"), null).show();
    }

    private void fetchSub() {
        final String u = subEt.getText().toString().trim();
        if (!u.startsWith("http://") && !u.startsWith("https://")) {
            Toast.makeText(this, L.t("لینک اشتراک باید با https:// شروع شود"), Toast.LENGTH_LONG).show();
            return;
        }
        if (busy) return;
        busy = true;
        Chain.setSubUrl(this, u);
        Core.log(L.t("کانفیگ + سایفون: دریافت اشتراک …"));
        new Thread(() -> {
            String msg;
            int n = 0;
            boolean ok = false;
            try {
                List<String> ls = Chain.fetchSub(this, u);
                n = Chain.add(this, ls);
                msg = L.t("اشتراک: ") + ls.size() + L.t(" کانفیگ، ") + n + L.t(" تازه");
                ok = true;
            } catch (Exception e) {
                msg = L.t("دریافت اشتراک ناموفق: ") + e.getMessage();
            }
            Core.log(L.t("کانفیگ + سایفون: ") + msg);
            final String m = msg;
            final boolean test = ok && n > 0;
            ui.post(() -> {
                busy = false;
                Toast.makeText(this, m, Toast.LENGTH_LONG).show();
                render();
                if (test) testAll();
            });
        }, "o76-chain-sub").start();
    }

    private void testAll() {
        if (Chain.testing || !Chain.configured(this)) return;
        if (!Chain.available(this)) {
            Toast.makeText(this, L.t("هستهٔ کانفیگ + سایفون روی این گوشی نصب نیست"), Toast.LENGTH_LONG).show();
            return;
        }
        new Thread(() -> Chain.testAll(getApplicationContext()), "o76-chain-test").start();
    }

    private void render() {
        sig = Chain.testing + "|" + Chain.list(this).size() + "|" + Chain.selected(this) + "|" + Chain.testStatus;
        listBox.removeAllViews();
        List<JSONObject> l = Chain.list(this);
        JSONObject cur = Chain.current(this);
        if (l.isEmpty()) {
            listBox.addView(text(L.t("هنوز کانفیگی نیست — «چسباندن از کلیپ‌بورد» یا «افزودن دستی» را بزنید."), 13, false));
            return;
        }
        // tested-OK first (by latency), then untested, then failed
        java.util.Collections.sort(l, (a, c) -> Long.compare(rank(a), rank(c)));
        for (final JSONObject o : l) {
            final String u = o.optString("u");
            boolean sel = cur != null && u.equals(cur.optString("u"));
            long ms = o.optLong("ms", 0);
            String state = ms > 0 ? "✓ " + ms + "ms" : ms < 0 ? "✗ " + o.optString("e") : L.t("تست نشده");
            TextView t = new TextView(this);
            t.setText((sel ? "● " : "") + o.optString("n") + "\n" + Chain.scheme(u) + "   " + state);
            t.setTextSize(13);
            t.setTextColor(ms < 0 ? Color.rgb(153, 27, 27) : Color.rgb(30, 30, 30));
            t.setPadding(dp(12), dp(8), dp(12), dp(8));
            GradientDrawable bg = new GradientDrawable();
            bg.setCornerRadius(dp(8));
            bg.setColor(sel ? Color.rgb(207, 250, 254) : Color.WHITE);
            bg.setStroke(dp(1), sel ? ACCENT : Color.rgb(226, 232, 240));
            t.setBackground(bg);
            t.setOnClickListener(v -> {
                Chain.select(this, u);
                Toast.makeText(this, L.t("انتخاب شد: ") + o.optString("n"), Toast.LENGTH_SHORT).show();
                render();
            });
            t.setOnLongClickListener(v -> {
                new AlertDialog.Builder(this).setTitle(L.t("حذف این کانفیگ؟")).setMessage(o.optString("n"))
                        .setPositiveButton(L.t("حذف"), (d, w) -> { Chain.remove(this, u); render(); })
                        .setNegativeButton(L.t("لغو"), null).show();
                return true;
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
            lp.setMargins(0, dp(3), 0, dp(3));
            listBox.addView(t, lp);
        }
    }

    private static long rank(JSONObject o) {
        long ms = o.optLong("ms", 0);
        return ms > 0 ? ms : ms == 0 ? 1_000_000 : 2_000_000;
    }
}
