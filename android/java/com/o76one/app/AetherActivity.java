package com.o76one.app;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

/** v1.6 Aether mode settings: protocol, SNI, via bridge (HTTP/2 only), exit not in Iran. Persian RTL. */
public class AetherActivity extends Activity {
    private static final int ACCENT = Color.rgb(14, 116, 144);
    private boolean changed;
    private CheckBox viaBridge;
    private TextView bridgeTv, idTv, sniTitle;
    private LinearLayout sniBox;

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

    /** a horizontally scrolling row of choice chips; the selected one is filled */
    private void choices(LinearLayout parent, final String[] values, final String[] labels, String current,
                         final Core.Fn<String> onPick) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setBaselineAligned(false);
        HorizontalScrollView hs = new HorizontalScrollView(this);
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

        TextView title = text("Aether", 24, true);
        title.setGravity(Gravity.CENTER);
        title.setTextColor(ACCENT);
        root.addView(title, new LinearLayout.LayoutParams(-1, -2));

        if (!Aether.available(this)) {
            root.addView(text(L.t("هستهٔ Aether فقط برای گوشی‌های ۶۴ بیتی (arm64) همراه برنامه است و روی این گوشی نصب نشده."), 15, true));
            setContentView(sv);
            return;
        }

        root.addView(text(L.t("هستهٔ Aether نسخهٔ ") + Aether.VERSION + L.t(" (CluvexStudio) تونل WARP را با اسکن دروازهٔ خودش، ضد DPI و ")
                + L.t("تأیید واقعی عبور داده باز می‌کند و 076one ترافیک گوشی را از راه پروکسی SOCKS محلی آن عبور می‌دهد. ")
                + L.t("از همان حساب WARP این گوشی استفاده می‌شود و دستگاه جدیدی ثبت نمی‌شود (جز WireGuard/gool که یک‌بار هویت WG می‌سازند)."), 13, false));

        root.addView(text(L.t("پروتکل"), 17, true));
        choices(root, new String[]{Aether.P_H2, Aether.P_H3, Aether.P_WG, Aether.P_GOOL},
                new String[]{L.t("HTTP/2 (پیشنهادی)"), "HTTP/3", "WireGuard", "gool"}, Aether.proto(this), v -> {
                    Aether.setProto(this, v);
                    render();
                });
        root.addView(text(L.t("HTTP/2 روی TCP است و با تکه‌تکه کردن ClientHello از فیلترینگ رد می‌شود؛ HTTP/3 و WireGuard به UDP نیاز دارند ")
                + L.t("(روی بسیاری از اینترنت‌های ایران بسته است). gool یک تونل WireGuard داخل MASQUE (روی HTTP/2) است با IP خروجی متفاوت."), 12, false));

        sniTitle = text("SNI", 17, true);
        root.addView(sniTitle);
        sniBox = new LinearLayout(this);
        sniBox.setOrientation(LinearLayout.VERTICAL);
        root.addView(sniBox, new LinearLayout.LayoutParams(-1, -2));
        List<String> snis = new ArrayList<>(Core.snis(this));
        if (!snis.contains(Aether.CF_SNI)) snis.add(Aether.CF_SNI);
        String[] sv2 = snis.toArray(new String[0]);
        choices(sniBox, sv2, sv2, Aether.sni(this), v -> Aether.setSni(this, v));
        sniBox.addView(text(L.t("پیش‌فرض: اولین SNI فهرست تنظیمات. www.cloudflare.com پیش‌فرض خود Aether است."), 12, false));

        viaBridge = new CheckBox(this);
        viaBridge.setText(L.t("از طریق پل (فقط HTTP/2)"));
        viaBridge.setTypeface(Typeface.DEFAULT_BOLD);
        viaBridge.setTextSize(15);
        viaBridge.setChecked(Aether.viaBridge(this));
        viaBridge.setOnCheckedChangeListener((v, on) -> { Aether.setViaBridge(this, on); changed = true; render(); });
        root.addView(viaBridge);
        bridgeTv = text("", 12, false);
        root.addView(bridgeTv);
        Button bridgePage = MainActivity.Ui.button(this, L.t("صفحهٔ پل (به‌روزرسانی و تست)"), R.drawable.ic_link, Color.rgb(100, 116, 139));
        bridgePage.setOnClickListener(v -> startActivity(new Intent(this, BridgeActivity.class)));
        root.addView(MainActivity.Ui.row(this, bridgePage));

        CheckBox exit = new CheckBox(this);
        exit.setText(L.t("خروجی غیر ایران (!IR)"));
        exit.setTypeface(Typeface.DEFAULT_BOLD);
        exit.setTextSize(15);
        exit.setChecked(Aether.exitNotIR(this));
        exit.setOnCheckedChangeListener((v, on) -> { Aether.setExitNotIR(this, on); changed = true; });
        root.addView(exit);
        root.addView(text(L.t("پیشنهاد: خاموش. ") + Aether.exitIrNote()
                + L.t(" اگر روشن باشد و تونل دو بار به‌خاطر خروجی IR رد شود، این گزینه خودکار خاموش می‌شود."), 12, false));

        idTv = text("", 12, false);
        idTv.setPadding(dp(10), dp(8), dp(10), dp(8));
        GradientDrawable g = new GradientDrawable();
        g.setColor(Color.WHITE);
        g.setCornerRadius(dp(8));
        g.setStroke(dp(1), Color.rgb(203, 213, 225));
        idTv.setBackground(g);
        LinearLayout.LayoutParams ilp = new LinearLayout.LayoutParams(-1, -2);
        ilp.setMargins(0, dp(8), 0, dp(8));
        root.addView(idTv, ilp);

        Button use = MainActivity.Ui.button(this, L.t("استفاده از حالت Aether"), R.drawable.ic_check, ACCENT);
        use.setOnClickListener(v -> {
            Core.setMode(this, Core.MODE_AETHER);
            Core.prefs(this).edit().putBoolean("aSeen", true).apply();
            Core.log(L.t("حالت اتصال: Aether"));
            boolean active = O76VpnService.state == O76VpnService.ST_ON || O76VpnService.state == O76VpnService.ST_CONNECTING
                    || O76VpnService.state == O76VpnService.ST_RECONNECTING;
            Toast.makeText(this, active ? L.t("حالت Aether — برای اعمال، یک بار قطع و وصل کنید") : L.t("حالت Aether انتخاب شد"), Toast.LENGTH_LONG).show();
            finish();
        });
        root.addView(MainActivity.Ui.row(this, use));

        TextView lic = text("Aether v" + Aether.VERSION + L.t(" — CluvexStudio — مجوز AGPL-3.0 — ") + Aether.REPO
                + L.t("\n(متن مجوز و منبع: تنظیمات ← درباره)"), 11, false);
        lic.setTextColor(Color.rgb(100, 116, 139));
        root.addView(lic);

        setContentView(sv);
        render();
    }

    private void render() {
        if (viaBridge == null) return;
        String p = Aether.proto(this);
        boolean h2 = Aether.P_H2.equals(p);
        viaBridge.setEnabled(h2);
        viaBridge.setAlpha(h2 ? 1f : 0.5f);
        boolean wg = Aether.P_WG.equals(p);
        sniTitle.setVisibility(wg ? View.GONE : View.VISIBLE);
        sniBox.setVisibility(wg ? View.GONE : View.VISIBLE);
        String bu = Aether.bestIntlBridge(this);
        if (!h2) {
            bridgeTv.setText(L.t("پل فقط با HTTP/2 به کار می‌رود (HTTP/3 و WireGuard به UDP نیاز دارند)."));
        } else if (bu == null) {
            bridgeTv.setText(L.t("هنوز پل سالمی با دسترسی به خارج (intl=1) نیست — در صفحهٔ پل فهرست را به‌روز و تست کنید. تا آن موقع مستقیم وصل می‌شود."));
        } else {
            bridgeTv.setText(L.t("بهترین پل با دسترسی به خارج: ") + Bridges.keyOf(bu) + (Aether.viaBridge(this) ? L.t(" (استفاده می‌شود)") : ""));
        }
        StringBuilder sb = new StringBuilder(L.t("هویت‌ها: "));
        sb.append(Aether.masqueToml(this).isFile() ? L.t("MASQUE ✓ (از حساب WARP)") : Core.hasConfig(this) ? L.t("MASQUE: هنگام اتصال ساخته می‌شود") : L.t("MASQUE: حساب WARP نیست — اول ثبت‌نام کنید"));
        if (wg) sb.append("\nWireGuard: ").append(Aether.wgToml(this).isFile() ? "✓" : L.t("بار اول یک‌بار ثبت می‌شود (از طریق پل اگر باشد)"));
        if (Aether.P_GOOL.equals(p)) sb.append("\ngool: ").append(Aether.goolToml(this).isFile() ? "✓" : L.t("بار اول یک‌بار ثبت می‌شود (از طریق پل اگر باشد)"));
        idTv.setText(sb.toString());
    }

    @Override
    protected void onResume() {
        super.onResume();
        render();
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (changed) Core.log(L.t("تنظیمات Aether تغییر کرد: ") + Aether.protoLabel(Aether.proto(this)) + " SNI=" + Aether.sni(this)
                + (Aether.bridgeApplies(this) ? " via bridge" : "") + (Aether.exitNotIR(this) ? " exit!IR" : ""));
        changed = false;
    }
}
