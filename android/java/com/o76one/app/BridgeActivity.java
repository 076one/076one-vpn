package com.o76one.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipboardManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/** v1.3 "پل (پروکسی)" screen: on/off, proxy list sorted by real delay, test, update lists, paste, sources. Persian RTL. */
public class BridgeActivity extends Activity {
    private static final int ACCENT = Color.rgb(194, 65, 12);
    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView statusTv, countTv;
    private Button testBtn, fetchBtn;
    private LinearLayout listBox;
    private Switch onSw, irSw;
    // v1.8.4: what runs through the bridge proxy
    private MainActivity.Ui.IconBtn viaWarp, viaPsi;
    private TextView viaHint;
    private String viaShown = "";
    private int rendered = -1;

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

    private Button button(String s, int icon) {
        return MainActivity.Ui.button(this, s, icon, ACCENT);
    }

    private LinearLayout row(View... vs) {
        return MainActivity.Ui.row(this, vs);
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        ScrollView sv = new ScrollView(this);
        // no EditText on this screen: block focus so list updates never scroll the page
        sv.setDescendantFocusability(ViewGroup.FOCUS_BLOCK_DESCENDANTS);
        sv.setNestedScrollingEnabled(true);
        sv.setBackgroundColor(Color.rgb(245, 247, 250));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(16), dp(16), dp(24));
        root.setLayoutDirection(L.dir());
        root.setTextDirection(L.tdir());
        sv.addView(root);

        TextView title = text(L.t("پل (پروکسی)"), 24, true);
        title.setGravity(Gravity.CENTER);
        title.setTextColor(ACCENT);
        root.addView(title, new LinearLayout.LayoutParams(-1, -2));
        root.addView(text(L.t("وقتی اتصال مستقیم به Cloudflare (162.159.198.x) بسته است: گوشی ← پروکسی عمومی SOCKS5/SOCKS4/HTTP ← Cloudflare MASQUE (HTTP/2). ")
                + L.t("رمزنگاری TLS با کلید سرورِ سنجاق‌شده سرتاسری است؛ پروکسی فقط داده‌ی رمزشده می‌بیند. با پل فقط HTTP/2 استفاده می‌شود."), 13, false));

        onSw = new Switch(this);
        onSw.setText(L.t("استفاده از پل هنگام اتصال"));
        onSw.setTextSize(17);
        onSw.setTypeface(Typeface.DEFAULT_BOLD);
        onSw.setChecked(Bridges.enabled(this));
        onSw.setPadding(0, dp(8), 0, dp(8));
        onSw.setOnCheckedChangeListener((v, on) -> {
            Bridges.setEnabled(this, on);
            boolean active = O76VpnService.state == O76VpnService.ST_ON || O76VpnService.state == O76VpnService.ST_RECONNECTING
                    || O76VpnService.state == O76VpnService.ST_CONNECTING;
            Toast.makeText(this, on ? (Bridges.workingCount(this) == 0 ? L.t("پل روشن شد — هنگام اتصال، اول پروکسی‌ها تست می‌شوند (تا ۲ دقیقه)") : L.t("پل روشن شد"))
                    : L.t("پل خاموش شد — اتصال مستقیم"), Toast.LENGTH_LONG).show();
            if (active) Toast.makeText(this, L.t("برای اعمال، یک بار قطع و دوباره وصل کنید"), Toast.LENGTH_LONG).show();
        });
        root.addView(onSw);

        // v1.8.4: WARP (MASQUE, as before) or Psiphon through the bridge proxy
        root.addView(text(L.t("از طریق پروکسی:"), 15, true));
        viaWarp = MainActivity.Ui.choiceButton(this, "WARP", 0, ACCENT, !Bridges.viaPsiphon(this));
        viaPsi = MainActivity.Ui.choiceButton(this, L.t("سایفون"), 0, ACCENT, Bridges.viaPsiphon(this));
        viaWarp.setOnClickListener(v -> setVia(Bridges.VIA_WARP));
        viaPsi.setOnClickListener(v -> setVia(Bridges.VIA_PSI));
        root.addView(row(viaWarp, viaPsi));
        viaHint = text("", 12, false);
        viaHint.setTextColor(Color.rgb(100, 116, 139));
        root.addView(viaHint);

        // v1.5: only Iranian proxies (Bridges.isIROnly)
        irSw = new Switch(this);
        irSw.setText(L.t("فقط پروکسی‌های ایران"));
        irSw.setTextSize(16);
        irSw.setTypeface(Typeface.DEFAULT_BOLD);
        irSw.setPadding(0, dp(6), 0, 0);
        irSw.setChecked(Bridges.isIROnly(this));
        irSw.setOnCheckedChangeListener((v, on) -> {
            if (on == Bridges.isIROnly(this)) return;
            Bridges.setIROnly(this, on);
            Core.log(L.t("پل: فقط پروکسی‌های ایران ") + (on ? L.t("روشن") : L.t("خاموش")));
            rendered = -1;
            Toast.makeText(this, on ? L.t("فقط پروکسی‌های ایران — «تست پل‌ها» را دوباره بزنید") : L.t("همهٔ پروکسی‌ها"), Toast.LENGTH_LONG).show();
        });
        root.addView(irSw, new LinearLayout.LayoutParams(-1, -2));
        TextView irHint = text(L.t("فقط پروکسی‌هایی که IP آن‌ها در ایران است تست و استفاده می‌شوند؛ رسیدن به آن‌ها از داخل ایران معمولاً سریع‌تر و پایدارتر است."), 12, false);
        irHint.setTextColor(Color.rgb(100, 116, 139));
        root.addView(irHint);

        testBtn = button(L.t("تست پل‌ها"), R.drawable.ic_speed);
        fetchBtn = button(L.t("به‌روزرسانی فهرست‌ها"), R.drawable.ic_download);
        root.addView(row(testBtn, fetchBtn));
        Button pasteBtn = button(L.t("چسباندن پروکسی"), R.drawable.ic_paste);
        Button autoBtn = button(L.t("انتخاب خودکار پل"), R.drawable.ic_auto);
        root.addView(row(pasteBtn, autoBtn));
        Button srcBtn = button(L.t("منابع فهرست (URL)"), R.drawable.ic_link);
        Button clearBtn = button(L.t("پاک کردن همه"), R.drawable.ic_delete);
        root.addView(row(srcBtn, clearBtn));

        testBtn.setOnClickListener(v -> {
            if (Bridges.busy) { Bridges.stop(); return; }
            if (!Bridges.viaPsiphon(this) && !Core.hasConfig(this)) { Toast.makeText(this, L.t("اول در صفحهٔ اصلی ثبت‌نام WARP کنید"), Toast.LENGTH_LONG).show(); return; }
            if (Bridges.userList(this).isEmpty() && Bridges.poolSize(this) == 0 && Bridges.results(this).isEmpty()) {
                Toast.makeText(this, L.t("فهرست خالی است؛ اول فهرست‌ها دریافت می‌شود"), Toast.LENGTH_SHORT).show();
                Bridges.startFetch(this, () -> ui.post(() -> {
                    if (Bridges.poolSize(this) > 0) Bridges.startTest(this, null);
                }));
            } else {
                Bridges.startTest(this, null);
            }
        });
        fetchBtn.setOnClickListener(v -> {
            if (Bridges.busy) return;
            Bridges.startFetch(this, null);
        });
        pasteBtn.setOnClickListener(v -> showPaste());
        autoBtn.setOnClickListener(v -> {
            Bridges.setPinned(this, "");
            Toast.makeText(this, L.t("پل به‌صورت خودکار (کمترین تاخیر واقعی) انتخاب می‌شود"), Toast.LENGTH_SHORT).show();
            rendered = -1;
        });
        srcBtn.setOnClickListener(v -> showSources());
        clearBtn.setOnClickListener(v -> new AlertDialog.Builder(this).setTitle(L.t("پاک کردن همهٔ پروکسی‌ها؟"))
                .setMessage(L.t("فهرست چسبانده‌شده، فهرست دانلودشده و نتایج تست پاک می‌شوند."))
                .setPositiveButton(L.t("پاک کن"), (d, w) -> { Bridges.clearAll(this); rendered = -1; })
                .setNegativeButton(L.t("لغو"), null).show());

        statusTv = text("", 13, false);
        root.addView(statusTv);
        countTv = text("", 13, false);
        root.addView(countTv);
        root.addView(text(L.t("پل‌ها — مرتب بر اساس تاخیر واقعی (لمس = سنجاق کردن، لمس طولانی = حذف):"), 15, true));
        listBox = new LinearLayout(this);
        listBox.setOrientation(LinearLayout.VERTICAL);
        root.addView(MainActivity.Ui.boundedBox(this, listBox, 220), new LinearLayout.LayoutParams(-1, -2));
        root.addView(text(L.t("روش تست: ۵۰ پروکسی هم‌زمان (حداکثر ۱۰۰۰ در هر بار، هر بار پروکسی‌های بعدی فهرست): اتصال به پروکسی + هندشیک TLS سرور MASQUE از داخل آن؛ ")
                + L.t("سپس روی سریع‌ترین‌ها تست واقعی (تونل + cdn-cgi/trace با warp=on + دانلود 100KB). هنگام اتصال اگر داده رد نشود، خودکار پل بعدی انتخاب می‌شود.\n")
                + L.t("فرمت‌های قابل قبول: socks5://ip:port ، socks4://ip:port ، http://ip:port ، ip:port ، user:pass@ip:port ، socks5://user:pass@ip:port"), 12, false));

        setContentView(sv);
        tick.run();
    }

    private void setVia(String v) {
        if (v.equals(Bridges.via(this))) return;
        if (Bridges.busy) { Toast.makeText(this, L.t("اول تست در حال اجرا را متوقف کنید"), Toast.LENGTH_SHORT).show(); return; }
        Bridges.setVia(this, v);
        rendered = -1;
        boolean active = O76VpnService.state == O76VpnService.ST_ON || O76VpnService.state == O76VpnService.ST_RECONNECTING
                || O76VpnService.state == O76VpnService.ST_CONNECTING;
        Toast.makeText(this, Bridges.viaLabel(this) + (Bridges.workingCount(this) == 0 ? L.t(" — «تست پل‌ها» را بزنید") : "")
                + (active && Bridges.enabled(this) ? L.t("\nبرای اعمال، یک بار قطع و دوباره وصل کنید") : ""), Toast.LENGTH_LONG).show();
        refresh();
    }

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            refresh();
            ui.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onDestroy() {
        ui.removeCallbacks(tick);
        super.onDestroy();
    }

    private void refresh() {
        MainActivity.Ui.setText(statusTv, Bridges.status);
        String tl = Bridges.busy ? L.t("توقف") : L.t("تست پل‌ها");
        if (!android.text.TextUtils.equals(testBtn.getText(), tl)) {
            testBtn.setText(tl);
            MainActivity.Ui.setIcon(testBtn, Bridges.busy ? R.drawable.ic_stop : R.drawable.ic_speed, Color.WHITE);
        }
        fetchBtn.setEnabled(!Bridges.busy);
        fetchBtn.setAlpha(Bridges.busy ? 0.5f : 1f);
        if (onSw.isChecked() != Bridges.enabled(this)) onSw.setChecked(Bridges.enabled(this));
        if (irSw.isChecked() != Bridges.isIROnly(this)) irSw.setChecked(Bridges.isIROnly(this));
        String via = Bridges.via(this);
        if (!via.equals(viaShown)) {
            viaShown = via;
            boolean psi = Bridges.VIA_PSI.equals(via);
            MainActivity.Ui.styleChoice(viaWarp, ACCENT, !psi);
            MainActivity.Ui.styleChoice(viaPsi, ACCENT, psi);
            MainActivity.Ui.setText(viaHint, psi
                    ? L.t("سایفون: گوشی ← پروکسی ← سایفون؛ خروجی یک سرور سایفون است. حساب WARP لازم نیست. تست: هندشیک پروکسی، بعد اتصال واقعی سایفون از طریق بهترین‌ها (۳ هم‌زمان، تا ۷۵ ثانیه). SOCKS5، HTTP و SOCKS4 پشتیبانی می‌شوند.")
                    : L.t("WARP: گوشی ← پروکسی ← Cloudflare MASQUE (HTTP/2)؛ حساب WARP لازم است."));
        }
        String inUse = O76VpnService.bridgeInUse;
        MainActivity.Ui.setText(countTv, L.t("چسبانده‌شده: ") + Bridges.userList(this).size() + L.t("   دانلودشده: ") + Bridges.poolSize(this)
                + L.t("   سالم: ") + Bridges.workingCount(this) + (inUse.isEmpty() ? "" : L.t("\nدر حال استفاده: ") + inUse));
        int v = Bridges.version() * 31 + inUse.hashCode() + Bridges.pinned(this).hashCode() + via.hashCode();
        if (v != rendered) { rendered = v; renderList(); }
    }

    private void renderList() {
        listBox.removeAllViews();
        List<JSONObject> l = Bridges.results(this);
        String pin = Bridges.pinned(this);
        String inUse = O76VpnService.bridgeInUse;
        if (l.isEmpty()) {
            listBox.addView(text(L.t("هنوز پلی تست نشده — «به‌روزرسانی فهرست‌ها» و سپس «تست پل‌ها» را بزنید، یا پروکسی بچسبانید."), 13, false));
            return;
        }
        int shown = 0;
        for (JSONObject o : l) {
            if (shown++ >= 60) break;
            final String k = o.optString("k");
            int ok = o.optInt("ok", -1);
            boolean isPin = !pin.isEmpty() && Bridges.addrOf(pin).equals(Bridges.addrOf(k));
            boolean isUse = !inUse.isEmpty() && Bridges.addrOf(inUse).equals(Bridges.addrOf(k));
            boolean cool = Bridges.coolingDown(o);
            boolean auth = Bridges.hasAuth(o.optString("u", ""));
            String line1 = (isPin ? "" : isUse ? "● " : "○ ") + Bridges.typeLabel(k) + "  " + Bridges.addrOf(k)
                    + (ok == 1 ? "   " + o.optLong("rms") + "ms · " + o.optLong("kbps") + " KB/s  " + (cool ? L.t("✗ (اخیراً قطع شد)") : "✓")
                    : ok == 0 ? "   ✗"
                    : L.t("   هندشیک ") + o.optLong("hs") + "ms  ?");
            boolean psiRes = "p".equals(o.optString("kind"));
            if (psiRes) line1 = (isPin ? "" : isUse ? "● " : "○ ") + Bridges.typeLabel(k) + "  " + Bridges.addrOf(k)
                    + (ok == 1 ? "   " + o.optLong("rms") + "ms  " + (cool ? L.t("✗ (اخیراً قطع شد)") : "✓")
                    : ok == 0 ? "   ✗" : L.t("   هندشیک ") + o.optLong("hs") + "ms  ?");
            String line2 = psiRes ? ((ok == 1 ? L.t("سایفون ") + o.optString("colo", "") : ok == 0 ? o.optString("e", "") : "")
                    + (o.optLong("hs", 0) > 0 && ok == 1 ? L.t("  (هندشیک ") + o.optLong("hs") + "ms)" : "")
                    + (isUse ? L.t("   ⟵ در حال استفاده") : ""))
                    : (ok == 1 ? "Cloudflare " + o.optString("colo", "") + "  " + o.optString("ep", "") : "")
                    + (o.optLong("hs", 0) > 0 && ok == 1 ? L.t("  (هندشیک ") + o.optLong("hs") + "ms)" : "")
                    + (isUse ? L.t("   ⟵ در حال استفاده") : "");
            TextView t = new TextView(this);
            String body = line2.isEmpty() ? line1 : line1 + "\n" + line2;
            // icons instead of the 📌 / 🔑 emoji
            CharSequence cs = auth ? MainActivity.Ui.withIcon(this, R.drawable.ic_key, Color.rgb(146, 64, 14), body) : body;
            if (isPin) cs = new android.text.SpannableStringBuilder(MainActivity.Ui.withIcon(this, R.drawable.ic_pin, ACCENT, "")).append(cs);
            t.setText(cs);
            t.setTextDirection(View.TEXT_DIRECTION_LTR);
            t.setTextSize(14);
            t.setTextColor(ok == 0 || cool ? Color.rgb(153, 27, 27) : ok == 1 ? Color.rgb(21, 128, 61) : Color.rgb(30, 30, 30));
            t.setPadding(dp(12), dp(8), dp(12), dp(8));
            GradientDrawable g = new GradientDrawable();
            g.setColor(isPin ? Color.rgb(255, 237, 213) : isUse ? Color.rgb(207, 250, 254) : ok == 0 ? Color.rgb(254, 242, 242) : Color.WHITE);
            g.setCornerRadius(dp(8));
            g.setStroke(dp(1), Color.rgb(203, 213, 225));
            t.setBackground(g);
            t.setOnClickListener(v -> {
                if (isPin) {
                    Bridges.setPinned(this, "");
                    Toast.makeText(this, L.t("سنجاق برداشته شد — انتخاب خودکار"), Toast.LENGTH_SHORT).show();
                } else {
                    Bridges.setPinned(this, k);
                    Toast.makeText(this, L.t("این پل سنجاق شد (تعویض خودکار پل خاموش)"), Toast.LENGTH_SHORT).show();
                }
                rendered = -1;
            });
            t.setOnLongClickListener(v -> {
                Bridges.remove(this, k);
                rendered = -1;
                return true;
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
            lp.setMargins(0, dp(3), 0, dp(3));
            listBox.addView(t, lp);
        }
    }

    private void showPaste() {
        final EditText et = new EditText(this);
        et.setHint("socks5://1.2.3.4:1080\nhttp://5.6.7.8:8080\nuser:pass@9.9.9.9:1080");
        et.setMinLines(6);
        et.setTextSize(12);
        et.setTextDirection(View.TEXT_DIRECTION_LTR);
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm.hasPrimaryClip() && cm.getPrimaryClip().getItemCount() > 0) {
                CharSequence cs = cm.getPrimaryClip().getItemAt(0).coerceToText(this);
                if (cs != null && cs.toString().matches("(?s).*\\d+\\.\\d+\\.\\d+\\.\\d+:\\d+.*")) et.setText(cs);
            }
        } catch (Exception ignored) { }
        new AlertDialog.Builder(this).setTitle(L.t("چسباندن پروکسی (هر خط یکی)"))
                .setMessage(L.t("بدون نوع (ip:port) خودکار تشخیص داده می‌شود (SOCKS5 → HTTP → SOCKS4). نام کاربری/رمز فقط روی گوشی ذخیره می‌شود و در گزارش نمی‌آید."))
                .setView(et)
                .setPositiveButton(L.t("افزودن و تست"), (d, w) -> {
                    int n = Bridges.addPasted(this, et.getText().toString());
                    Toast.makeText(this, n + L.t(" پروکسی جدید اضافه شد"), Toast.LENGTH_LONG).show();
                    rendered = -1;
                    if (n > 0 && (Bridges.viaPsiphon(this) || Core.hasConfig(this))) Bridges.startTest(this, null);
                })
                .setNegativeButton(L.t("لغو"), null).show();
    }

    private void showSources() {
        StringBuilder sb = new StringBuilder(L.t("منابع پیش‌فرض (اول مستقیم از GitHub، بعد آینهٔ jsDelivr):\n"));
        for (String s : Bridges.DEFAULT_SOURCES) {
            String[] p = s.split("\\|");
            sb.append("• ").append(p[0].toUpperCase()).append("  ").append(p[1].replace("https://", "")).append('\n');
        }
        final EditText et = new EditText(this);
        StringBuilder u = new StringBuilder();
        for (String s : Bridges.userSources(this)) u.append(s).append('\n');
        et.setText(u.toString().trim());
        et.setHint("https://example.com/socks5.txt");
        et.setMinLines(3);
        et.setTextSize(12);
        et.setTextDirection(View.TEXT_DIRECTION_LTR);
        TextView tv = text(sb.toString() + L.t("\nURLهای خودتان (هر خط یکی؛ فهرست متنی ip:port یا socks5://…):"), 11, false);
        tv.setTextDirection(View.TEXT_DIRECTION_LTR);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), dp(8));
        box.addView(tv);
        box.addView(et);
        ScrollView sv = new ScrollView(this);
        sv.addView(box);
        new AlertDialog.Builder(this).setTitle(L.t("منابع فهرست پروکسی")).setView(sv)
                .setPositiveButton(L.t("ذخیره"), (d, w) -> {
                    List<String> l = new ArrayList<>();
                    for (String s : et.getText().toString().split("[\\s,]+")) {
                        s = s.trim();
                        if ((s.startsWith("http://") || s.startsWith("https://")) && !l.contains(s)) l.add(s);
                    }
                    Bridges.saveUserSources(this, l);
                    Toast.makeText(this, l.size() + L.t(" منبع شخصی ذخیره شد"), Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(L.t("لغو"), null).show();
    }
}
