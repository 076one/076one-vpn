package com.o76one.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
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

/** v1.8 وارپ+ mode options: variant (WARP / WARP-in-WARP / Psiphon), Psiphon country, WARP endpoint. Persian RTL. */
public class WarpPlusActivity extends Activity {
    private static final int ACCENT = Color.rgb(14, 116, 144);
    private LinearLayout countryBox;
    private EditText epEt;
    private TextView idTv;

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
            });
            row.addView(bs[i], wrap());
        }
    }

    private CheckBox check(String s, boolean on, Core.Fn<Boolean> f) {
        CheckBox cb = new CheckBox(this);
        cb.setText(s);
        cb.setTypeface(Typeface.DEFAULT_BOLD);
        cb.setTextSize(15);
        cb.setChecked(on);
        cb.setOnCheckedChangeListener((v, b) -> f.accept(b));
        return cb;
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

        TextView title = text(L.t("وارپ+"), 24, true);
        title.setGravity(Gravity.CENTER);
        title.setTextColor(ACCENT);
        root.addView(title, new LinearLayout.LayoutParams(-1, -2));
        root.addView(text(L.t("WARP روی WireGuard (UDP) با هستهٔ warp-plus. «سایفون» ترافیک را داخل WARP به شبکهٔ سایفون می‌برد و خروجی ")
                + L.t("در کشوری است که انتخاب می‌کنید؛ «وارپ در وارپ» دو لایه WARP است. هر دو به UDP نیاز دارند؛ اگر اینترنت شما UDP را ")
                + L.t("می‌بندد، endpoint یا پورت دیگری امتحان کنید."), 13, false));

        root.addView(text(L.t("نوع"), 17, true));
        choices(root, new String[]{WarpPlus.V_PSIPHON, WarpPlus.V_GOOL, WarpPlus.V_WARP},
                new String[]{L.t("سایفون"), L.t("وارپ در وارپ"), L.t("وارپ ساده")}, WarpPlus.variant(this), v -> {
                    WarpPlus.setVariant(this, v);
                    countryBox.setVisibility(WarpPlus.V_PSIPHON.equals(v) ? View.VISIBLE : View.GONE);
                });

        countryBox = new LinearLayout(this);
        countryBox.setOrientation(LinearLayout.VERTICAL);
        countryBox.addView(text(L.t("کشور خروجی سایفون"), 17, true));
        choices(countryBox, WarpPlus.COUNTRIES, WarpPlus.COUNTRIES, WarpPlus.country(this), v -> WarpPlus.setCountry(this, v));
        countryBox.setVisibility(WarpPlus.V_PSIPHON.equals(WarpPlus.variant(this)) ? View.VISIBLE : View.GONE);
        root.addView(countryBox, new LinearLayout.LayoutParams(-1, -2));

        root.addView(text(L.t("Endpoint وارپ (endip)"), 17, true));
        epEt = new EditText(this);
        epEt.setHint(L.t("خالی = خودکار، مثل 162.159.192.1:2408"));
        epEt.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        epEt.setSingleLine(true);
        epEt.setTextDirection(View.TEXT_DIRECTION_LTR);
        epEt.setText(WarpPlus.endpoint(this));
        root.addView(epEt, new LinearLayout.LayoutParams(-1, -2));
        Button save = MainActivity.Ui.button(this, L.t("ذخیرهٔ endpoint"), R.drawable.ic_save, ACCENT);
        save.setOnClickListener(v -> {
            String e = epEt.getText().toString().trim();
            if (!e.isEmpty() && !e.matches("^(\\d{1,3}(\\.\\d{1,3}){3}|\\[[0-9a-fA-F:]+\\]):\\d{1,5}$")) {
                Toast.makeText(this, L.t("قالب درست: IP:پورت (مثل 188.114.97.3:878)"), Toast.LENGTH_LONG).show();
                return;
            }
            WarpPlus.setEndpoint(this, e);
            Toast.makeText(this, e.isEmpty() ? L.t("endpoint خودکار") : L.t("endpoint ذخیره شد"), Toast.LENGTH_SHORT).show();
        });
        Button pick = MainActivity.Ui.button(this, L.t("پیشنهادها"), R.drawable.ic_search, Color.rgb(100, 116, 139));
        pick.setOnClickListener(v -> {
            final String[] eps = {"162.159.192.1:2408", "162.159.193.10:500", "162.159.195.1:4500", "188.114.97.3:878",
                    "188.114.98.224:1701", "162.159.192.191:1180", "188.114.96.1:894", "162.159.193.5:8854"};
            new AlertDialog.Builder(this).setTitle(L.t("endpoint پیشنهادی")).setItems(eps, (d, w) -> epEt.setText(eps[w])).show();
        });
        root.addView(MainActivity.Ui.row(this, save, pick));
        root.addView(check(L.t("اسکن خودکار endpoint سالم (وقتی خالی است)"), WarpPlus.scan(this), on -> WarpPlus.setScan(this, on)));
        root.addView(check(L.t("فقط IPv4"), WarpPlus.v4only(this), on -> WarpPlus.setV4only(this, on)));
        root.addView(text(L.t("endpointی که پیدا و استفاده می‌شود در گزارش ثبت می‌شود؛ می‌توانید آن را این‌جا ذخیره کنید تا دفعهٔ بعد سریع‌تر وصل شود."), 12, false));

        idTv = text("", 13, false);
        root.addView(idTv);
        Button reset = MainActivity.Ui.button(this, L.t("ساخت هویت WARP تازه"), R.drawable.ic_refresh, Color.rgb(100, 116, 139));
        reset.setOnClickListener(v -> new AlertDialog.Builder(this).setTitle(L.t("هویت تازه؟"))
                .setMessage(L.t("هویت‌های WARP این حالت پاک می‌شوند و در اتصال بعدی دوباره ثبت می‌شوند (از طریق پل سالم اگر باشد)."))
                .setPositiveButton(L.t("بله"), (d, w) -> { WarpPlus.resetIdentity(this); renderId(); })
                .setNegativeButton(L.t("لغو"), null).show());
        root.addView(MainActivity.Ui.row(this, reset));

        Button use = MainActivity.Ui.button(this, L.t("استفاده از حالت وارپ+"), R.drawable.ic_check, ACCENT);
        use.setOnClickListener(v -> {
            String e = epEt.getText().toString().trim();
            if (!e.equals(WarpPlus.endpoint(this)) && (e.isEmpty() || e.matches("^(\\d{1,3}(\\.\\d{1,3}){3}|\\[[0-9a-fA-F:]+\\]):\\d{1,5}$")))
                WarpPlus.setEndpoint(this, e);
            Core.setMode(this, Core.MODE_WPLUS);
            Core.log(L.t("حالت اتصال: وارپ+ — ") + WarpPlus.describe(this));
            boolean active = O76VpnService.state == O76VpnService.ST_ON || O76VpnService.state == O76VpnService.ST_CONNECTING
                    || O76VpnService.state == O76VpnService.ST_RECONNECTING;
            Toast.makeText(this, active ? L.t("حالت وارپ+ — برای اعمال، یک بار قطع و وصل کنید") : L.t("حالت وارپ+ انتخاب شد"), Toast.LENGTH_LONG).show();
            finish();
        });
        root.addView(MainActivity.Ui.row(this, use));

        TextView lic = text(L.t("هستهٔ این حالت: warp-plus ") + WarpPlus.VERSION + L.t(" (bepass-org، مجوز MIT) — ") + WarpPlus.REPO
                + L.t("\nسایفون: psiphon-tunnel-core (Psiphon Inc.، مجوز GPL-3.0). متن مجوزها در تنظیمات ← مجوزها."), 12, false);
        lic.setTextColor(Color.rgb(100, 116, 139));
        root.addView(lic);
        renderId();
        setContentView(sv);
    }

    private void renderId() {
        boolean a = WarpPlus.hasIdentity(this, "primary"), s = WarpPlus.hasIdentity(this, "secondary");
        idTv.setText(L.t("هویت WARP این حالت: ") + (a ? L.t("اول ✓") : L.t("اول هنوز ساخته نشده")) + (s ? L.t("، دوم ✓") : WarpPlus.V_GOOL.equals(WarpPlus.variant(this)) ? L.t("، دوم در اتصال اول ساخته می‌شود") : ""));
    }
}
