package com.o76one.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.style.ImageSpan;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ListView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

public class MainActivity extends Activity {
    private static final int REQ_VPN = 1, REQ_FILE = 2, REQ_SAVE = 3;
    /** Share/clipboard payloads go through a Binder transaction (~1 MB, UTF-16); larger logs are saved to a file instead. */
    private static final int MAX_INLINE = 200_000;
    private static final int ACCENT = Color.rgb(14, 116, 144);

    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView statusTv, speedTv, selectedTv, accountTv, scanTv, logTv, bridgeHintTv;
    private Button bridgeBtn, chainBtn, aetherBtn, foxBtn, wpBtn;
    private Ui.IconBtn[] modeBtns;
    // v1.6: the 4th mode (Aether) exists only where libaether.so is installed (arm64-v8a)
    // v1.7: 5th mode Firefox (all ABIs)
    // v1.8.2: «کانفیگ + سایفون» (Config + Psiphon) in the slot of the removed Worker mode
    private static final String[] ALL_MODES = {Core.MODE_WARP, Core.MODE_BRIDGE, Core.MODE_CHAIN, Core.MODE_AETHER, Core.MODE_FOX, Core.MODE_WPLUS};
    private static String[] ALL_LABELS = {"WARP", "پل", "کانفیگ", "Aether", "Firefox", "وارپ+"};
    private static final int[] ALL_ICONS = {R.drawable.ic_auto, R.drawable.ic_link, R.drawable.ic_cloud, R.drawable.ic_layers, R.drawable.ic_key, R.drawable.ic_activity};
    private String[] MODES;
    private Button connectBtn, scanBtn, testBtn, regBtn, autoBtn;
    private LinearLayout listBox;
    private volatile boolean busyTest, busyReg;
    private String renderedSig = "";
    private String uiSig = "";           // connect button / mode buttons: rebuilt only when this changes
    private String pendingSave;          // text waiting for the ACTION_CREATE_DOCUMENT result

    // ------------------------------------------------------------ UI
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
        return Ui.button(this, s, icon, ACCENT);
    }

    private LinearLayout row(View... vs) {
        return Ui.row(this, vs);
    }

    private void pickLanguage() {
        String[] items = new String[L.CODES.length];
        for (int i = 0; i < items.length; i++) items[i] = L.FLAGS[i] + "  " + L.NAMES[i];
        new android.app.AlertDialog.Builder(this)
                .setSingleChoiceItems(items, L.index(), (d, w) -> {
                    d.dismiss();
                    if (!L.CODES[w].equals(L.lang())) {
                        L.set(this, L.CODES[w]);
                        recreate();
                    }
                }).show();
    }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        // v1.7.1 layout: one scrolling page; the server list is a bounded card at its end (like the log).
        LinearLayout outer = new LinearLayout(this);
        outer.setOrientation(LinearLayout.VERTICAL);
        outer.setBackgroundColor(Color.rgb(245, 247, 250));
        outer.setLayoutDirection(L.dir());
        outer.setTextDirection(L.tdir());

        ScrollView sv = new ScrollView(this);
        // nothing inside may take focus: a focused child makes ScrollView jump to it on every layout pass
        sv.setDescendantFocusability(ViewGroup.FOCUS_BLOCK_DESCENDANTS);
        sv.setNestedScrollingEnabled(true);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(16), dp(16), dp(16));
        sv.addView(root);
        outer.addView(sv, new LinearLayout.LayoutParams(-1, 0, 1f));

        TextView title = text("076ONE", 30, false);
        title.setGravity(Gravity.CENTER);
        title.setTextColor(ACCENT);
        // v1.7.2: Cinzel (SIL OFL 1.1) title font, bold weight of the variable font
        try {
            title.setTypeface(android.graphics.Typeface.createFromAsset(getAssets(), "fonts/Cinzel.ttf"));
            if (android.os.Build.VERSION.SDK_INT >= 26) title.setFontVariationSettings("'wght' 700");
            else title.setTypeface(title.getTypeface(), android.graphics.Typeface.BOLD);
        } catch (Throwable ignored) { }
        title.setLetterSpacing(0.06f);
        // v1.8.1: language button (flag + code) at the top left
        android.widget.FrameLayout head = new android.widget.FrameLayout(this);
        head.addView(title, new android.widget.FrameLayout.LayoutParams(-1, -2, Gravity.CENTER));
        TextView lb = new TextView(this);
        int li = L.index();
        lb.setText(L.FLAGS[li] + " " + L.CODES[li].toUpperCase(java.util.Locale.US));
        lb.setTextSize(13);
        lb.setTextColor(Color.rgb(60, 64, 72));
        lb.setPadding(dp(10), dp(5), dp(10), dp(5));
        android.graphics.drawable.GradientDrawable lbg = new android.graphics.drawable.GradientDrawable();
        lbg.setCornerRadius(dp(14));
        lbg.setColor(Color.WHITE);
        lbg.setStroke(dp(1), Color.rgb(210, 214, 220));
        lb.setBackground(lbg);
        lb.setContentDescription("Language");
        lb.setOnClickListener(v -> pickLanguage());
        head.addView(lb, new android.widget.FrameLayout.LayoutParams(-2, -2, Gravity.LEFT | Gravity.CENTER_VERTICAL));
        root.addView(head, new LinearLayout.LayoutParams(-1, -2));

        // v1.4: connection mode selector
        TextView ml = text(L.t("حالت اتصال:"), 14, true);
        root.addView(ml);
        java.util.List<Integer> idx = new java.util.ArrayList<>();
        for (int i = 0; i < ALL_MODES.length; i++) {
            if (Core.MODE_AETHER.equals(ALL_MODES[i]) && !Aether.available(this)) continue; // arm64 only: hidden on 32-bit phones
            if (Core.MODE_CHAIN.equals(ALL_MODES[i]) && !Chain.available(this)) continue;
            if (Core.MODE_FOX.equals(ALL_MODES[i]) && !Fox.available(this)) continue;
            if (Core.MODE_WPLUS.equals(ALL_MODES[i]) && !WarpPlus.available(this)) continue;
            idx.add(i);
        }
        final int nModes = idx.size();
        MODES = new String[nModes];
        modeBtns = new Ui.IconBtn[nModes];
        String cm = Core.mode(this);
        for (int j = 0; j < nModes; j++) {
            final int i = idx.get(j);
            MODES[j] = ALL_MODES[i];
            final String m = MODES[j];
            Ui.IconBtn mb = Ui.choiceButton(this, L.t(ALL_LABELS[i]), ALL_ICONS[i], ACCENT, m.equals(cm));
            mb.setOnClickListener(v -> onModeClick(m));
            modeBtns[j] = mb;
        }
        if (nModes > 4) {
            // v1.8: six modes do not fit one row on a phone -> two rows
            int half = (nModes + 1) / 2;
            root.addView(Ui.row(this, Ui.MODE_H, java.util.Arrays.copyOfRange(modeBtns, 0, half)), new LinearLayout.LayoutParams(-1, -2));
            root.addView(Ui.row(this, Ui.MODE_H, java.util.Arrays.copyOfRange(modeBtns, half, nModes)), new LinearLayout.LayoutParams(-1, -2));
        } else {
            root.addView(Ui.row(this, Ui.MODE_H, modeBtns), new LinearLayout.LayoutParams(-1, -2));
        }

        connectBtn = new Button(this);
        connectBtn.setTextSize(20);
        connectBtn.setCompoundDrawablesRelative(null, Ui.icon(this, R.drawable.ic_power, Color.WHITE, 44), null, null);
        connectBtn.setCompoundDrawablePadding(dp(Ui.GAP));
        connectBtn.setPadding(0, dp(28), 0, dp(20));
        connectBtn.setGravity(Gravity.CENTER);
        connectBtn.setElevation(dp(6));
        connectBtn.setTextColor(Color.WHITE);
        connectBtn.setTypeface(Typeface.DEFAULT_BOLD);
        connectBtn.setAllCaps(false);
        LinearLayout.LayoutParams clp = new LinearLayout.LayoutParams(dp(160), dp(160));
        clp.gravity = Gravity.CENTER_HORIZONTAL;
        clp.setMargins(0, dp(16), 0, dp(12));
        root.addView(connectBtn, clp);
        connectBtn.setOnClickListener(v -> onConnectClick());

        statusTv = text("", 18, true);
        statusTv.setGravity(Gravity.CENTER);
        root.addView(statusTv, new LinearLayout.LayoutParams(-1, -2));
        speedTv = text("", 15, false);
        speedTv.setGravity(Gravity.CENTER);
        root.addView(speedTv, new LinearLayout.LayoutParams(-1, -2));
        selectedTv = text("", 14, false);
        selectedTv.setGravity(Gravity.CENTER);
        root.addView(selectedTv, new LinearLayout.LayoutParams(-1, -2));

        Button logBtn = button(L.t("خروجی گزارش"), R.drawable.ic_share);
        logBtn.setOnClickListener(v -> exportLog());
        autoBtn = button(L.t("انتخاب خودکار سرور"), R.drawable.ic_auto);
        autoBtn.setOnClickListener(v -> {
            Core.setPinned(this, "");
            Toast.makeText(this, L.t("سرور به‌صورت خودکار (کمترین پینگ) انتخاب می‌شود"), Toast.LENGTH_SHORT).show();
            renderList();
            refresh();
        });
        root.addView(row(autoBtn, logBtn));

        scanBtn = button(L.t("اسکن سرورها"), R.drawable.ic_search);
        testBtn = button(L.t("تست سرور"), R.drawable.ic_speed);
        root.addView(row(scanBtn, testBtn));
        regBtn = button(L.t("ثبت‌نام WARP"), R.drawable.ic_user_add);
        Button importBtn = button(L.t("وارد کردن کانفیگ"), R.drawable.ic_file);
        root.addView(row(regBtn, importBtn));
        Button setBtn = button(L.t("تنظیمات (SNI، ضد DPI، MTU، پورت‌ها)"), R.drawable.ic_settings);
        root.addView(row(setBtn));
        bridgeBtn = button(L.t("پل (پروکسی)"), R.drawable.ic_link);
        bridgeBtn.setOnClickListener(v -> startActivity(new Intent(this, BridgeActivity.class)));
        chainBtn = button(L.t("کانفیگ + سایفون (vless، vmess، trojan، ss)"), R.drawable.ic_cloud);
        chainBtn.setOnClickListener(v -> startActivity(new Intent(this, ChainActivity.class)));
        if (Chain.available(this)) root.addView(row(bridgeBtn, chainBtn));
        else root.addView(row(bridgeBtn));
        aetherBtn = button(L.t("Aether (پروتکل، SNI، پل)"), R.drawable.ic_layers);
        aetherBtn.setOnClickListener(v -> startActivity(new Intent(this, AetherActivity.class)));
        foxBtn = button(L.t("Firefox (ورود، پروتکل، مکان)"), R.drawable.ic_key);
        foxBtn.setOnClickListener(v -> startActivity(new Intent(this, FoxActivity.class)));
        if (Aether.available(this) && Fox.available(this)) root.addView(row(aetherBtn, foxBtn));
        else if (Aether.available(this)) root.addView(row(aetherBtn));
        else if (Fox.available(this)) root.addView(row(foxBtn));
        wpBtn = button(L.t("وارپ+ (سایفون، وارپ در وارپ، endpoint)"), R.drawable.ic_activity);
        wpBtn.setOnClickListener(v -> startActivity(new Intent(this, WarpPlusActivity.class)));
        if (WarpPlus.available(this)) root.addView(row(wpBtn));
        bridgeHintTv = text("", 14, true);
        bridgeHintTv.setTextColor(Color.rgb(154, 52, 18));
        bridgeHintTv.setPadding(dp(12), dp(8), dp(12), dp(8));
        GradientDrawable hg = new GradientDrawable();
        hg.setColor(Color.rgb(255, 237, 213));
        hg.setCornerRadius(dp(8));
        bridgeHintTv.setBackground(hg);
        bridgeHintTv.setOnClickListener(v -> startActivity(new Intent(this,
                Core.MODE_CHAIN.equals(Core.mode(this)) ? ChainActivity.class : BridgeActivity.class)));
        bridgeHintTv.setVisibility(View.GONE);
        root.addView(bridgeHintTv, new LinearLayout.LayoutParams(-1, -2));
        scanBtn.setOnClickListener(v -> onScanClick());
        testBtn.setOnClickListener(v -> onTestClick());
        regBtn.setOnClickListener(v -> confirmRegister());
        importBtn.setOnClickListener(v -> showImport());
        setBtn.setOnClickListener(v -> startActivity(new Intent(this, SettingsActivity.class)));

        accountTv = text("", 13, false);
        root.addView(accountTv);
        scanTv = text("", 13, false);
        root.addView(scanTv);

        // ---- log: own bounded box (max ~220dp, own scroll); never selectable/focusable (that caused the scroll jumps)
        LinearLayout logHead = new LinearLayout(this);
        logHead.setOrientation(LinearLayout.HORIZONTAL);
        logHead.setGravity(Gravity.CENTER_VERTICAL);
        logHead.setPadding(0, dp(8), 0, dp(2));
        TextView logTitle = text(L.t("گزارش (جدیدترین بالا)"), 13, true);
        logHead.addView(logTitle, new LinearLayout.LayoutParams(0, -2, 1f));
        logHead.addView(Ui.iconButton(this, R.drawable.ic_copy, ACCENT, L.t("کپی ۲۰۰ خط آخر"), v -> copyLastLines()));
        logHead.addView(Ui.iconButton(this, R.drawable.ic_share, ACCENT, L.t("خروجی گزارش"), v -> exportLog()));
        logHead.addView(Ui.iconButton(this, R.drawable.ic_delete, Color.rgb(185, 28, 28), L.t("پاک کردن گزارش"), v -> confirmClearLog()));
        root.addView(logHead, new LinearLayout.LayoutParams(-1, -2));
        logTv = new TextView(this);
        logTv.setTextSize(11);
        logTv.setTypeface(Typeface.MONOSPACE);
        logTv.setTextDirection(View.TEXT_DIRECTION_LTR);
        logTv.setTextColor(Color.rgb(80, 80, 80));
        logTv.setTextIsSelectable(false);
        logTv.setFocusable(false);
        logTv.setFocusableInTouchMode(false);
        logTv.setOnLongClickListener(v -> { exportLog(); return true; });
        root.addView(Ui.boundedBox(this, logTv, 220), new LinearLayout.LayoutParams(-1, -2));

        // ---- v1.7.1: server list at the end of the page, same style as the log (header + bounded card)
        LinearLayout ph = new LinearLayout(this);
        ph.setOrientation(LinearLayout.HORIZONTAL);
        ph.setGravity(Gravity.CENTER_VERTICAL);
        ph.setPadding(0, dp(12), 0, dp(2));
        TextView pt = text(L.t("سرورها (مرتب بر اساس تاخیر واقعی)"), 13, true);
        ph.addView(pt, new LinearLayout.LayoutParams(0, -2, 1f));
        ph.addView(Ui.iconButton(this, R.drawable.ic_auto, ACCENT, L.t("انتخاب خودکار سرور"), v -> {
            Core.setPinned(this, "");
            Toast.makeText(this, L.t("سرور به‌صورت خودکار (کمترین پینگ) انتخاب می‌شود"), Toast.LENGTH_SHORT).show();
            renderList();
            refresh();
        }));
        ph.addView(Ui.iconButton(this, R.drawable.ic_refresh, ACCENT, L.t("اسکن سرورها"), v -> onScanClick()));
        root.addView(ph, new LinearLayout.LayoutParams(-1, -2));
        TextView pst = text(L.t("لمس = سنجاق · لمس طولانی = حذف"), 11, false);
        pst.setTextColor(Color.rgb(100, 116, 139));
        root.addView(pst);
        listBox = new LinearLayout(this);
        listBox.setOrientation(LinearLayout.VERTICAL);
        root.addView(Ui.boundedBox(this, listBox, 320), new LinearLayout.LayoutParams(-1, -2));

        setContentView(outer);

        Core.snis(this); // migrates the v1.0 single SNI
        if (Build.VERSION.SDK_INT >= 33) {
            try { requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 9); } catch (Exception ignored) { }
        }
        renderList();
        // auto-register only when there is no account at all on this phone (never because of a mode switch)
        if (!Core.hasConfig(this) && !Core.MODE_CHAIN.equals(Core.mode(this)) && !Core.MODE_FOX.equals(Core.mode(this)) && !Core.MODE_WPLUS.equals(Core.mode(this))
                && !(Core.MODE_BRIDGE.equals(Core.mode(this)) && Bridges.viaPsiphon(this))) register(L.t("خودکار: حساب WARP روی این گوشی نیست"));
        else Servers.maybeAutoScan(this, L.t("فهرست خالی یا قدیمی‌تر از ۶ ساعت"));
        tick.run();
        // v1.8.5: quiet update check, at most once a day (Settings → "check automatically"); a dialog only when newer
        ui.postDelayed(() -> { if (!isFinishing()) Updater.quietCheck(this); }, 8000);
    }

    @Override
    protected void onResume() {
        super.onResume();
        renderedSig = "";
        if (Core.hasConfig(this) && !busyReg) Servers.maybeAutoScan(this, L.t("فهرست خالی یا قدیمی‌تر از ۶ ساعت"));
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
        int st = O76VpnService.state;
        boolean active = st == O76VpnService.ST_ON || st == O76VpnService.ST_CONNECTING || st == O76VpnService.ST_RECONNECTING;
        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.OVAL);
        int color;
        String label, status;
        switch (st) {
            case O76VpnService.ST_ON:
                if (O76VpnService.noData) { color = Color.rgb(234, 88, 12); label = L.t("قطع اتصال"); status = "⚠ " + O76VpnService.stateMsg; }
                else { color = Color.rgb(22, 163, 74); label = L.t("قطع اتصال"); status = L.t("متصل ✓"); }
                break;
            case O76VpnService.ST_CONNECTING: color = Color.rgb(234, 179, 8); label = L.t("لغو"); status = L.t("در حال اتصال… ") + O76VpnService.stateMsg; break;
            case O76VpnService.ST_RECONNECTING: color = Color.rgb(234, 179, 8); label = L.t("قطع اتصال"); status = O76VpnService.stateMsg; break;
            case O76VpnService.ST_ERROR: color = Color.rgb(220, 38, 38); label = L.t("اتصال"); status = O76VpnService.stateMsg; break;
            default: color = Color.rgb(100, 116, 139); label = L.t("اتصال"); status = L.t("قطع");
        }
        g.setColor(color);
        String mode = Core.mode(this);
        boolean bOn = Bridges.enabled(this);
        boolean wMode = Core.MODE_CHAIN.equals(mode); // v1.8.2: Config + Psiphon (was Worker)
        boolean aMode = Core.MODE_AETHER.equals(mode);
        String sig = color + "|" + label + "|" + mode + "|" + bOn;
        if (!sig.equals(uiSig)) {
            uiSig = sig;
            connectBtn.setBackground(new RippleDrawable(ColorStateList.valueOf(0x40FFFFFF), g, null));
            connectBtn.setText(label);
            for (int i = 0; i < modeBtns.length; i++) {
                Ui.styleChoice(modeBtns[i], ACCENT, MODES[i].equals(mode));
            }
            Ui.setIcon(aetherBtn, Core.MODE_AETHER.equals(mode) ? R.drawable.ic_check : R.drawable.ic_layers, Color.WHITE);
            Ui.setIcon(foxBtn, Core.MODE_FOX.equals(mode) ? R.drawable.ic_check : R.drawable.ic_key, Color.WHITE);
            Ui.setIcon(wpBtn, Core.MODE_WPLUS.equals(mode) ? R.drawable.ic_check : R.drawable.ic_activity, Color.WHITE);
            // active state is shown with a check icon instead of a "✓" glyph in the label
            Ui.setIcon(bridgeBtn, bOn ? R.drawable.ic_check : R.drawable.ic_link, Color.WHITE);
            Ui.setIcon(chainBtn, wMode ? R.drawable.ic_check : R.drawable.ic_cloud, Color.WHITE);
        }
        Ui.setText(statusTv, L.t("وضعیت: ") + status);
        statusTv.setTextColor(color);
        if (active) {
            long rr = O76VpnService.realRtt;
            Ui.setText(speedTv, L.t("⬇ دانلود: ") + Core.fmtSpeed(O76VpnService.downBps) + L.t("   ⬆ آپلود: ") + Core.fmtSpeed(O76VpnService.upBps)
                    + L.t("\nمجموع: ⬇ ") + Core.fmtBytes(O76VpnService.rxTotal) + "  ⬆ " + Core.fmtBytes(O76VpnService.txTotal)
                    + L.t("\nتاخیر واقعی (از داخل تونل): ") + (O76VpnService.noData ? L.t("— داده برنمی‌گردد") : rr > 0 ? rr + "ms" : "…"));
        } else {
            Ui.setText(speedTv, L.t("⬇ دانلود: 0 B/s   ⬆ آپلود: 0 B/s"));
        }
        String pin = Core.pinned(this);
        String sel;
        if (active && !O76VpnService.proto.isEmpty()) {
            sel = (O76VpnService.bridgeInUse.isEmpty() ? "" : L.t("از طریق پل ⇄ ")) + L.t("پروتکل: ") + Core.protoLabel(O76VpnService.proto) + L.t("   سرور: ") + O76VpnService.endpoint
                    + "\nSNI: " + O76VpnService.sniUsed + (pin.isEmpty() ? L.t("   (انتخاب خودکار)") : L.t("   (سنجاق‌شده)"));
        } else if (pin.isEmpty()) {
            sel = L.t("انتخاب سرور: خودکار — کمترین پینگ سالم");
        } else {
            String[] k = pin.split("\\|");
            sel = L.t("سرور سنجاق‌شده: ") + (k.length == 3 ? Core.protoLabel(k[0]) + " " + k[1] + "\nSNI: " + k[2] : pin);
        }
        if (wMode) {
            if (active && Core.MODE_CHAIN.equals(O76VpnService.modeInUse)) {
                sel = L.t("حالت: کانفیگ + سایفون — ") + O76VpnService.endpoint
                        + (O76VpnService.chainStage.isEmpty() ? "" : "\n" + O76VpnService.chainStage)
                        + (O76VpnService.aetherExit.isEmpty() ? "" : L.t("\nخروجی: ") + O76VpnService.aetherExit);
            } else if (!Chain.configured(this)) {
                sel = L.t("حالت: کانفیگ + سایفون — هنوز کانفیگی اضافه نشده");
            } else {
                JSONObject cc = Chain.current(this);
                long ms = cc == null ? 0 : cc.optLong("ms", 0);
                sel = L.t("حالت: کانفیگ + سایفون — ") + Chain.describe(this)
                        + (ms > 0 ? "\n" + L.t("تاخیر کانفیگ: ") + ms + "ms" : ms < 0 ? "\n" + L.t("✗ تست آخر ناموفق: ") + cc.optString("e") : "");
            }
            if (!O76VpnService.modeInUse.isEmpty() && active && !O76VpnService.modeInUse.equals(mode)) sel += L.t("\n(حالت جدید بعد از اتصال دوباره اعمال می‌شود)");
        } else if (Core.MODE_WPLUS.equals(mode)) {
            if (active && Core.MODE_WPLUS.equals(O76VpnService.modeInUse)) {
                sel = L.t("حالت: وارپ+ — ") + O76VpnService.endpoint
                        + (O76VpnService.aetherExit.isEmpty() ? "" : L.t("\nخروجی: ") + O76VpnService.aetherExit);
            } else {
                sel = L.t("حالت: وارپ+ — ") + WarpPlus.describe(this);
            }
            if (!O76VpnService.modeInUse.isEmpty() && active && !O76VpnService.modeInUse.equals(mode)) sel += L.t("\n(حالت جدید بعد از اتصال دوباره اعمال می‌شود)");
        } else if (Core.MODE_FOX.equals(mode)) {
            if (active && Core.MODE_FOX.equals(O76VpnService.modeInUse)) {
                sel = L.t("حالت: Firefox — ") + O76VpnService.proto.toUpperCase() + "   " + O76VpnService.endpoint
                        + (O76VpnService.aetherExit.isEmpty() ? "" : L.t("\nخروجی: ") + O76VpnService.aetherExit)
                        + (O76VpnService.foxQuota.isEmpty() ? "" : L.t("\nسهمیه: ") + O76VpnService.foxQuota);
            } else {
                sel = L.t("حالت: Firefox — ") + (Fox.signedIn(this) ? Fox.email(this) : L.t("وارد نشده‌اید")) + "\n" + Fox.transportLabel(Fox.transport(this));
            }
            if (!O76VpnService.modeInUse.isEmpty() && active && !O76VpnService.modeInUse.equals(mode)) sel += L.t("\n(حالت جدید بعد از اتصال دوباره اعمال می‌شود)");
        } else if (aMode) {
            if (active && Core.MODE_AETHER.equals(O76VpnService.modeInUse)) {
                sel = L.t("حالت: Aether — ") + Aether.protoLabel(Aether.proto(this)) + L.t("   دروازه: ") + O76VpnService.endpoint
                        + (Aether.P_WG.equals(Aether.proto(this)) ? "" : "\nSNI: " + Aether.sni(this))
                        + (O76VpnService.aetherExit.isEmpty() ? "" : L.t("\nخروجی: ") + O76VpnService.aetherExit)
                        + (O76VpnService.bridgeInUse.isEmpty() ? "" : L.t("\nاز طریق پل: ") + O76VpnService.bridgeInUse);
            } else {
                sel = L.t("حالت: Aether — ") + Aether.protoLabel(Aether.proto(this))
                        + (Aether.P_WG.equals(Aether.proto(this)) ? "" : "   SNI: " + Aether.sni(this))
                        + (Aether.bridgeApplies(this) ? L.t("\nاز طریق پل (بهترین پل با دسترسی خارج)") : "")
                        + (Aether.exitNotIR(this) ? L.t("\nخروجی غیر ایران") : "");
            }
            if (!O76VpnService.modeInUse.isEmpty() && active && !O76VpnService.modeInUse.equals(mode)) sel += L.t("\n(حالت جدید بعد از اتصال دوباره اعمال می‌شود)");
        } else if (!O76VpnService.modeInUse.isEmpty() && active && !O76VpnService.modeInUse.equals(mode)) {
            sel += L.t("\n(حالت جدید بعد از اتصال دوباره اعمال می‌شود)");
        }
        if (wMode || aMode || Core.MODE_FOX.equals(mode) || Core.MODE_WPLUS.equals(mode)) {
            // nothing bridge-related in worker mode
        } else if (bOn && (Bridges.viaPsiphon(this) || (active && O76VpnService.bridgePsi))) {
            // v1.8.4 Bridge + Psiphon: no WARP server line; bridge, stage and Psiphon exit
            if (active && O76VpnService.bridgePsi && Core.MODE_BRIDGE.equals(O76VpnService.modeInUse)) {
                sel = L.t("حالت: پل + سایفون — ") + (O76VpnService.bridgeInUse.isEmpty() ? "…" : O76VpnService.bridgeInUse)
                        + (O76VpnService.chainStage.isEmpty() ? "" : "\n" + O76VpnService.chainStage)
                        + (O76VpnService.aetherExit.isEmpty() ? "" : L.t("\nخروجی: ") + O76VpnService.aetherExit);
                if (!Bridges.viaPsiphon(this)) sel += L.t("\n(حالت جدید بعد از اتصال دوباره اعمال می‌شود)");
            } else {
                JSONObject bb = Bridges.best(this);
                sel = L.t("حالت: پل + سایفون — ") + (bb == null ? L.t("هنوز پلی با سایفون تست نشده") : (Bridges.pinned(this).isEmpty() ? L.t("بهترین: ") : L.t("سنجاق‌شده: ")) + bb.optString("k")
                        + (bb.optLong("rms", 0) > 0 ? "  " + bb.optLong("rms") + "ms" : ""))
                        + L.t("\nخروجی: سرور سایفون") + (Chain.region(this).isEmpty() ? "" : " " + Chain.region(this));
                if (active && !O76VpnService.modeInUse.isEmpty()) sel += L.t("\n(حالت جدید بعد از اتصال دوباره اعمال می‌شود)");
            }
        } else if (active && !O76VpnService.bridgeInUse.isEmpty()) {
            sel = (O76VpnService.bridgePsi ? L.t("حالت: پل + سایفون — ") + O76VpnService.bridgeInUse
                    + (O76VpnService.aetherExit.isEmpty() ? "" : L.t("\nخروجی: ") + O76VpnService.aetherExit)
                    : L.t("حالت: پل + WARP\n") + sel + L.t("\nپل: ") + O76VpnService.bridgeInUse);
        } else if (bOn) {
            sel = L.t("حالت: پل + WARP\n") + sel;
            JSONObject bb = Bridges.best(this);
            sel += L.t("\nپل (پروکسی): روشن — ") + (bb == null ? L.t("هنوز پل سالمی تست نشده") : (Bridges.pinned(this).isEmpty() ? L.t("بهترین: ") : L.t("سنجاق‌شده: ")) + bb.optString("k"));
        }
        long dfa = Core.prefs(this).getLong("directFailAt", 0);
        boolean suggest = Core.MODE_WARP.equals(mode) && dfa > 0 && System.currentTimeMillis() - dfa < 6L * 3600 * 1000;
        boolean wHint = wMode && !Chain.configured(this);
        bridgeHintTv.setVisibility(suggest || wHint ? View.VISIBLE : View.GONE);
        if (wHint) Ui.setText(bridgeHintTv, L.t("⚠ حالت «کانفیگ + سایفون» انتخاب شده ولی هنوز کانفیگی اضافه نشده. برای چسباندن کانفیگ لمس کنید."));
        else if (suggest) Ui.setText(bridgeHintTv, L.t("⚠ تست واقعی اتصال مستقیم به هیچ سروری داده رد نکرد. حالت «پل پروکسی» را امتحان کنید (یا اگر کانفیگ دارید «کانفیگ + سایفون»). برای باز کردن پل لمس کنید."));
        String lp = Core.prefs(this).getString("lastProto", "");
        if (!lp.isEmpty() && !active && !wMode && !aMode) sel += L.t("\nآخرین پروتکل موفق: ") + Core.protoLabel(lp);
        if (Core.h2Only(this)) sel += L.t("\n(فقط HTTP/2)");
        sel += Core.bestMode(this) ? L.t("\nتنظیمات: بهترین (پیش‌فرض)") : L.t("\nتنظیمات: دستی");
        Ui.setText(selectedTv, sel);
        autoBtn.setEnabled(!pin.isEmpty());
        autoBtn.setAlpha(pin.isEmpty() ? 0.5f : 1f);
        if (Servers.scanning || !Servers.scanStatus.isEmpty()) {
            if (!busyTest) Ui.setText(scanTv, Servers.scanStatus);
        }
        String lsig = Core.epVersion() + "|" + pin + "|" + O76VpnService.proto + O76VpnService.endpoint + O76VpnService.sniUsed;
        if (!lsig.equals(renderedSig)) renderList();
        JSONObject cfg = Core.readConfig(this);
        String rl = busyReg ? L.t("در حال ثبت‌نام…") : cfg == null ? L.t("ثبت‌نام WARP") : L.t("ثبت‌نام دوباره");
        if (!TextUtils.equals(regBtn.getText(), rl)) regBtn.setText(rl);
        Ui.setText(accountTv, busyReg ? L.t("حساب WARP: در حال ثبت‌نام…") :
                cfg == null ? L.t("حساب WARP: ثبت نشده — «ثبت‌نام» یا «وارد کردن کانفیگ» را بزنید") :
                        L.t("حساب WARP: آماده (IP داخلی ") + cfg.optString("ipv4") + ")");
        Ui.setText(logTv, Core.logText());
        String sl = Servers.scanning ? L.t("توقف اسکن") : L.t("اسکن سرورها");
        if (!TextUtils.equals(scanBtn.getText(), sl)) {
            scanBtn.setText(sl);
            Ui.setIcon(scanBtn, Servers.scanning ? R.drawable.ic_stop : R.drawable.ic_search, Color.WHITE);
        }
        Ui.setText(testBtn, busyTest ? L.t("در حال تست…") : L.t("تست سرور"));
    }

    // ------------------------------------------------------------ list
    private void renderList() {
        listBox.removeAllViews();
        List<JSONObject> l = Core.endpoints(this);
        String pin = Core.pinned(this);
        boolean active = O76VpnService.state == O76VpnService.ST_ON || O76VpnService.state == O76VpnService.ST_RECONNECTING;
        String inUse = active ? O76VpnService.proto + "|" + O76VpnService.endpoint + "|" + O76VpnService.sniUsed : "";
        renderedSig = Core.epVersion() + "|" + pin + "|" + O76VpnService.proto + O76VpnService.endpoint + O76VpnService.sniUsed;
        if (l.isEmpty()) {
            listBox.addView(text(L.t("فهرست خالی است — «اسکن سرورها» را بزنید (اسکن خودکار هم انجام می‌شود)."), 13, false));
            return;
        }
        int shown = 0;
        for (JSONObject o : l) {
            if (shown++ >= 70) break;
            final String key = Core.key(o);
            String pr = o.optString("proto", "h2");
            int ok = o.optInt("ok", -1);
            long ms = o.optLong("ms", 0);
            int rok = o.optInt("rok", -1);
            boolean isPin = key.equals(pin), isUse = key.equals(inUse);
            TextView t = new TextView(this);
            String head = (isPin ? "" : isUse ? "● " : "○ ") + Core.protoLabel(pr) + "  " + o.optString("ep")
                    + (rok == 1 ? L.t("   واقعی ") + o.optLong("rms") + "ms · " + o.optLong("kbps") + " KB/s  ✓✓"
                    : rok == 0 ? L.t("   ✗ داده رد نشد")
                    : (ms > 0 ? L.t("   هندشیک ") + ms + "ms" : "") + (ok == 1 ? "  ✓" : ok == 0 ? "  ✗" : "  ?"));
            String body = head + "\nSNI: " + o.optString("sni") + (rok == 1 && ms > 0 ? L.t("   (هندشیک ") + ms + "ms)" : "") + (isUse ? L.t("   ⟵ در حال استفاده") : "");
            t.setText(isPin ? Ui.withIcon(this, R.drawable.ic_pin, Color.rgb(109, 40, 217), body) : body);
            t.setTextDirection(View.TEXT_DIRECTION_LTR);
            t.setTextSize(14);
            t.setTextColor(ok == 0 || rok == 0 ? Color.rgb(153, 27, 27) : rok == 1 ? Color.rgb(21, 128, 61) : Color.rgb(30, 30, 30));
            t.setPadding(dp(12), dp(8), dp(12), dp(8));
            GradientDrawable g = new GradientDrawable();
            g.setColor(isPin ? Color.rgb(237, 233, 254) : isUse ? Color.rgb(207, 250, 254) : (ok == 0 || rok == 0) ? Color.rgb(254, 242, 242) : Color.WHITE);
            g.setCornerRadius(dp(8));
            g.setStroke(dp(1), "h3".equals(pr) ? Color.rgb(167, 139, 250) : Color.rgb(203, 213, 225));
            t.setBackground(g);
            t.setOnClickListener(v -> {
                if (key.equals(Core.pinned(this))) {
                    Core.setPinned(this, "");
                    Toast.makeText(this, L.t("سنجاق برداشته شد — انتخاب خودکار"), Toast.LENGTH_SHORT).show();
                } else {
                    Core.setPinned(this, key);
                    Toast.makeText(this, L.t("این سرور سنجاق شد (انتخاب خودکار خاموش)"), Toast.LENGTH_SHORT).show();
                }
                renderList();
                refresh();
            });
            t.setOnLongClickListener(v -> {
                if (key.equals(Core.pinned(this))) Core.setPinned(this, "");
                Core.removeEndpoint(this, key);
                renderList();
                return true;
            });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
            lp.setMargins(0, dp(3), 0, dp(3));
            listBox.addView(t, lp);
        }
    }

    // ------------------------------------------------------------ connect
    private void onConnectClick() {
        int st = O76VpnService.state;
        if (st == O76VpnService.ST_ON || st == O76VpnService.ST_CONNECTING || st == O76VpnService.ST_RECONNECTING) {
            startService(new Intent(this, O76VpnService.class).setAction(O76VpnService.ACTION_STOP));
            return;
        }
        if (Core.MODE_FOX.equals(Core.mode(this))) {
            if (!Fox.signedIn(this)) {
                Toast.makeText(this, L.t("اول با حساب فایرفاکس خودتان وارد شوید"), Toast.LENGTH_LONG).show();
                startActivity(new Intent(this, FoxActivity.class));
                return;
            }
        } else if (Core.MODE_AETHER.equals(Core.mode(this))) {
            if (Aether.needsWarpConfig(this) && !Core.hasConfig(this)) {
                Toast.makeText(this, L.t("Aether از حساب WARP همین گوشی استفاده می‌کند؛ اول ثبت‌نام کنید یا کانفیگ وارد کنید"), Toast.LENGTH_LONG).show();
                return;
            }
        } else if (Core.MODE_CHAIN.equals(Core.mode(this))) {
            if (!Chain.configured(this)) {
                Toast.makeText(this, L.t("اول یک کانفیگ اضافه کنید"), Toast.LENGTH_LONG).show();
                startActivity(new Intent(this, ChainActivity.class));
                return;
            }
        } else if (Core.MODE_BRIDGE.equals(Core.mode(this)) && Bridges.viaPsiphon(this)) {
            // v1.8.4 Bridge + Psiphon: no WARP account needed (bridges are tested before connecting when none passed)
            if (!Chain.available(this)) {
                Toast.makeText(this, L.t("هستهٔ کانفیگ + سایفون روی این گوشی نصب نیست"), Toast.LENGTH_LONG).show();
                return;
            }
        } else if (!Core.hasConfig(this)) {
            Toast.makeText(this, L.t("اول ثبت‌نام کنید یا کانفیگ وارد کنید"), Toast.LENGTH_LONG).show();
            return;
        }
        Intent prep = VpnService.prepare(this);
        if (prep != null) startActivityForResult(prep, REQ_VPN);
        else onActivityResult(REQ_VPN, RESULT_OK, null);
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ_VPN && res == RESULT_OK) {
            O76VpnService.state = O76VpnService.ST_CONNECTING;
            startService(new Intent(this, O76VpnService.class).setAction(O76VpnService.ACTION_CONNECT));
        } else if (req == REQ_FILE && res == RESULT_OK && data != null && data.getData() != null) {
            importFromUri(data.getData());
        } else if (req == REQ_SAVE) {
            if (res == RESULT_OK && data != null && data.getData() != null) writeSaved(data.getData());
            else pendingSave = null;
        }
    }

    // ------------------------------------------------------------ mode
    private void onModeClick(String m) {
        if (m.equals(Core.mode(this))) return;
        Core.setMode(this, m);
        int st = O76VpnService.state;
        boolean active = st == O76VpnService.ST_ON || st == O76VpnService.ST_CONNECTING || st == O76VpnService.ST_RECONNECTING;
        Core.log(L.t("حالت اتصال: ") + Core.modeLabel(m));
        if (Core.MODE_CHAIN.equals(m) && !Chain.configured(this)) {
            startActivity(new Intent(this, ChainActivity.class));
        } else if (Core.MODE_FOX.equals(m) && !Fox.signedIn(this)) {
            startActivity(new Intent(this, FoxActivity.class));
        } else if (Core.MODE_WPLUS.equals(m) && !Core.prefs(this).getBoolean("wpSeen", false)) {
            Core.prefs(this).edit().putBoolean("wpSeen", true).apply();
            startActivity(new Intent(this, WarpPlusActivity.class)); // first time: show its options once
        } else if (Core.MODE_AETHER.equals(m) && !Core.prefs(this).getBoolean("aSeen", false)) {
            Core.prefs(this).edit().putBoolean("aSeen", true).apply();
            startActivity(new Intent(this, AetherActivity.class)); // first time: show its options once
        } else if (active) {
            Toast.makeText(this, L.t("حالت «") + Core.modeLabel(m) + L.t("» — برای اعمال، یک بار قطع و وصل کنید"), Toast.LENGTH_LONG).show();
        }
        refresh();
    }

    // ------------------------------------------------------------ scan
    private void onScanClick() {
        if (Servers.scanning) {
            Servers.stopScan();
            return;
        }
        if (!Core.hasConfig(this)) {
            Toast.makeText(this, L.t("اول ثبت‌نام کنید یا کانفیگ وارد کنید"), Toast.LENGTH_LONG).show();
            return;
        }
        Servers.startScan(this);
        refresh();
    }

    // ------------------------------------------------------------ test
    private void onTestClick() {
        if (busyTest) return;
        if (!Core.hasConfig(this)) {
            Toast.makeText(this, L.t("اول ثبت‌نام کنید یا کانفیگ وارد کنید"), Toast.LENGTH_LONG).show();
            return;
        }
        busyTest = true;
        scanTv.setText(L.t("تست واقعی: تونل + cdn-cgi/trace + دانلود 250KB از داخل تونل …"));
        refresh();
        new Thread(() -> {
            List<JSONObject> all = Core.endpoints(this);
            List<JSONObject> cand = new ArrayList<>();
            String pin = Core.pinned(this);
            if (!pin.isEmpty()) {
                JSONObject e = null;
                for (JSONObject o : all) if (Core.key(o).equals(pin)) e = o;
                if (e == null) e = Core.fromKey(pin);
                if (e != null) cand.add(e);
            } else {
                cand.addAll(Servers.pickDiverse(all, 6));
                // also re-test the best already-proven ones
                int n = 0;
                for (JSONObject o : all) {
                    if (n >= 2) break;
                    if (o.optInt("rok", -1) == 1 && "h2".equals(o.optString("proto"))) {
                        boolean dup = false;
                        for (JSONObject x : cand) if (Core.key(x).equals(Core.key(o))) dup = true;
                        if (!dup) { cand.add(o); n++; }
                    }
                }
            }
            if (cand.isEmpty()) cand.add(Core.entry("h2", Core.DEFAULT_EP, Core.firstSni(this), 0, -1));
            List<JSONObject> res = Servers.realTest(this, cand, 250000, 15, false);
            List<JSONObject> okL = new ArrayList<>(), bad = new ArrayList<>();
            for (JSONObject o : res) (o.optInt("rok") == 1 ? okL : bad).add(o);
            Collections.sort(okL, (x, y) -> Long.compare(Core.realScore(x), Core.realScore(y)));
            final StringBuilder sb = new StringBuilder();
            sb.append(L.t("تست واقعی = تونل MASQUE + درخواست cdn-cgi/trace (warp=on) + دانلود 250KB از داخل تونل.\n"))
              .append(L.t("تاخیر واقعی = زمان رفت‌وبرگشت یک درخواست از داخل تونل.\n\n"));
            for (JSONObject o : okL) {
                sb.append("✓ ").append(o.optString("ep")).append("  ").append(o.optLong("rms")).append("ms  ")
                  .append(o.optLong("kbps")).append(" KB/s\n   SNI: ").append(o.optString("sni")).append('\n');
            }
            for (JSONObject o : bad) {
                sb.append("✗ ").append(o.optString("ep")).append(L.t("  داده رد نشد\n   SNI: ")).append(o.optString("sni")).append('\n');
            }
            if (res.isEmpty()) sb.append(L.t("نتیجه‌ای نیامد؛ «خروجی گزارش» را ببینید."));
            final String title = okL.isEmpty() ? L.t("✗ هیچ سروری داده رد نکرد (") + res.size() + L.t(" تست)")
                    : "✓ " + okL.size() + L.t(" از ") + res.size() + L.t(" سرور داده رد کرد");
            final String sum = okL.isEmpty() ? L.t("✗ تست واقعی ناموفق") : L.t("✓ بهترین: ") + okL.get(0).optString("ep") + L.t(" — تاخیر واقعی ") + okL.get(0).optLong("rms") + "ms";
            ui.post(() -> {
                busyTest = false;
                renderList();
                scanTv.setText(sum);
                AlertDialog.Builder ab = new AlertDialog.Builder(this).setTitle(title).setMessage(sb.toString())
                        .setPositiveButton(L.t("باشه"), null);
                if (okL.isEmpty() && !Bridges.enabled(this)) {
                    ab.setMessage(sb + L.t("\nپیشنهاد: «پل (پروکسی)» را روشن کنید تا اتصال از طریق یک پروکسی عمومی برقرار شود."));
                    ab.setNeutralButton(L.t("پل (پروکسی)"), (d, w) -> startActivity(new Intent(this, BridgeActivity.class)));
                }
                ab.show();
                refresh();
            });
        }, "o76-test").start();
    }

    // ------------------------------------------------------------ log export
    private String lastLinesText() {
        return Core.scrub("076one log — last 200 lines (oldest first)\n" + O76App.tail(200), this);
    }

    private void copyLastLines() {
        copyText(L.t("۲۰۰ خط آخر گزارش"), lastLinesText());
    }

    private void copyText(String label, String s) {
        String body = s;
        boolean cut = s.length() > MAX_INLINE;
        if (cut) body = L.t("…(فقط انتهای گزارش؛ برای همه «ذخیره در فایل»)\n") + s.substring(s.length() - MAX_INLINE);
        try {
            android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            cm.setPrimaryClip(android.content.ClipData.newPlainText("076one log", body));
            Toast.makeText(this, label + L.t(" کپی شد (بدون کلید/توکن)") + (cut ? L.t(" — فقط انتهای آن") : ""), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, L.t("کپی نشد: ") + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void shareText(String title, String s) {
        if (s.length() > MAX_INLINE) {
            // too big for an Intent extra: offer the file instead of silently truncating
            new AlertDialog.Builder(this).setTitle(L.t("گزارش بزرگ است"))
                    .setMessage(L.t("حجم گزارش (") + Core.fmtBytes(s.length()) + L.t(") برای اشتراک مستقیم زیاد است. در فایل ذخیره شود (کامل)، یا فقط انتهای آن به اشتراک گذاشته شود؟"))
                    .setPositiveButton(L.t("ذخیره در فایل"), (d, w) -> saveToFile(s))
                    .setNeutralButton(L.t("فقط انتها"), (d, w) -> shareText(title, "…(truncated, see saved file)\n" + s.substring(s.length() - MAX_INLINE)))
                    .setNegativeButton(L.t("لغو"), null).show();
            return;
        }
        try {
            Intent i = new Intent(Intent.ACTION_SEND).setType("text/plain")
                    .putExtra(Intent.EXTRA_SUBJECT, "076one log")
                    .putExtra(Intent.EXTRA_TEXT, s);
            startActivity(Intent.createChooser(i, title));
        } catch (Exception e) {
            Toast.makeText(this, L.t("اشتراک نشد: ") + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void saveToFile(String s) {
        pendingSave = s;
        try {
            String name = "076one-log-" + new java.text.SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new java.util.Date()) + ".txt";
            Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                    .setType("text/plain").putExtra(Intent.EXTRA_TITLE, name);
            startActivityForResult(i, REQ_SAVE);
        } catch (Exception e) {
            pendingSave = null;
            Toast.makeText(this, L.t("ذخیره ممکن نشد: ") + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void writeSaved(Uri u) {
        final String s = pendingSave;
        pendingSave = null;
        if (s == null) return;
        new Thread(() -> {
            String err = null;
            try (OutputStream o = getContentResolver().openOutputStream(u, "w")) {
                if (o == null) throw new java.io.IOException("no stream");
                o.write(s.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                err = e.getMessage();
            }
            final String fe = err;
            ui.post(() -> Toast.makeText(this, fe == null ? L.t("گزارش در فایل ذخیره شد (") + Core.fmtBytes(s.length()) + ")" : L.t("ذخیره نشد: ") + fe,
                    Toast.LENGTH_LONG).show());
        }, "o76-save").start();
    }

    /** Builds a (scrubbed) export off the UI thread — the full log can be ~1 MB. */
    private void withText(boolean full, Core.Fn<String> then) {
        Toast.makeText(this, L.t("در حال آماده‌سازی گزارش…"), Toast.LENGTH_SHORT).show();
        new Thread(() -> {
            String s;
            try {
                s = full ? Core.diagnostics(this) + "\n\n==== full persistent log (oldest first) ====\n" + Core.scrub(O76App.readAll(), this)
                        : lastLinesText();
            } catch (Throwable e) {
                s = "export failed: " + e;
            }
            final String fs = s;
            ui.post(() -> { if (!isFinishing()) then.accept(fs); });
        }, "o76-export").start();
    }

    private void exportLog() {
        String[] items = {
                L.t("کپی ۲۰۰ خط آخر"),
                L.t("اشتراک ۲۰۰ خط آخر"),
                L.t("اشتراک گزارش کامل (تشخیصی + همهٔ گزارش)"),
                L.t("ذخیرهٔ گزارش کامل در فایل"),
                L.t("نمایش گزارش کامل"),
                L.t("ارسال گزارش خطا (GitHub)"),
                L.t("پاک کردن گزارش")};
        new AlertDialog.Builder(this).setTitle(L.t("خروجی گزارش (بدون کلید و توکن)"))
                .setItems(items, (d, w) -> {
                    switch (w) {
                        case 0: copyLastLines(); break;
                        case 1: shareText(L.t("اشتراک گزارش"), lastLinesText()); break;
                        case 2: withText(true, s -> shareText(L.t("اشتراک گزارش کامل"), s)); break;
                        case 3: withText(true, this::saveToFile); break;
                        case 4: withText(true, this::showFullLog); break;
                        case 5: Feedback.show(this); break;
                        default: confirmClearLog();
                    }
                })
                .setNegativeButton(L.t("بستن"), null).show();
    }

    private void confirmClearLog() {
        new AlertDialog.Builder(this).setTitle(L.t("پاک کردن گزارش؟"))
                .setMessage(L.t("همهٔ خطوط گزارش (حافظه و فایل) پاک می‌شوند."))
                .setPositiveButton(L.t("پاک کن"), (d, w) -> {
                    O76App.clear();
                    Ui.setText(logTv, "");
                    Toast.makeText(this, L.t("گزارش پاک شد"), Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(L.t("لغو"), null).show();
    }

    /** Full-screen viewer: the log in 120-line chunks inside a ListView, so even a 1 MB log scrolls smoothly. */
    private void showFullLog(final String s) {
        final android.app.Dialog dlg = new android.app.Dialog(this, android.R.style.Theme_DeviceDefault_Light_NoActionBar);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setLayoutDirection(L.dir());
        box.setBackgroundColor(Color.rgb(245, 247, 250));
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        bar.setPadding(dp(12), dp(8), dp(8), dp(8));
        bar.setBackgroundColor(Color.WHITE);
        bar.setElevation(dp(4));
        TextView tt = text(L.t("گزارش کامل — ") + Core.fmtBytes(s.length()), 15, true);
        bar.addView(tt, new LinearLayout.LayoutParams(0, -2, 1f));
        bar.addView(Ui.iconButton(this, R.drawable.ic_copy, ACCENT, L.t("کپی"), v -> copyText(L.t("گزارش"), s)));
        bar.addView(Ui.iconButton(this, R.drawable.ic_share, ACCENT, L.t("اشتراک"), v -> shareText(L.t("اشتراک گزارش کامل"), s)));
        bar.addView(Ui.iconButton(this, R.drawable.ic_save, ACCENT, L.t("ذخیره در فایل"), v -> saveToFile(s)));
        bar.addView(Ui.iconButton(this, R.drawable.ic_close, Color.rgb(71, 85, 105), L.t("بستن"), v -> dlg.dismiss()));
        box.addView(bar, new LinearLayout.LayoutParams(-1, -2));
        final List<String> chunks = new ArrayList<>();
        String[] lines = s.split("\n", -1);
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            cur.append(lines[i]);
            if ((i + 1) % 120 == 0 || i == lines.length - 1) { chunks.add(cur.toString()); cur.setLength(0); }
            else cur.append('\n');
        }
        ListView lv = new ListView(this);
        lv.setDivider(null);
        lv.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);
        lv.setAdapter(new android.widget.BaseAdapter() {
            public int getCount() { return chunks.size(); }
            public Object getItem(int p) { return chunks.get(p); }
            public long getItemId(int p) { return p; }
            public View getView(int p, View cv, ViewGroup parent) {
                TextView tv = cv instanceof TextView ? (TextView) cv : new TextView(MainActivity.this);
                tv.setTextSize(10);
                tv.setTypeface(Typeface.MONOSPACE);
                tv.setTextColor(Color.rgb(40, 40, 40));
                tv.setTextDirection(View.TEXT_DIRECTION_LTR);
                tv.setPadding(dp(10), 0, dp(10), 0);
                tv.setText(chunks.get(p));
                return tv;
            }
        });
        box.addView(lv, new LinearLayout.LayoutParams(-1, 0, 1f));
        dlg.setContentView(box);
        dlg.show();
        lv.setSelection(Math.max(0, chunks.size() - 1)); // open at the newest lines
    }

    // ------------------------------------------------------------ register / import
    private void confirmRegister() {
        if (!Core.hasConfig(this)) { register(L.t("دکمهٔ ثبت‌نام")); return; }
        // v1.5.1: an existing account is the normal case; a new one is only needed when Cloudflare rejects it.
        // The current account stays until a new registration has fully succeeded (and is kept as config.prev.json).
        new AlertDialog.Builder(this).setTitle(L.t("حساب WARP دارید — ثبت‌نام دوباره؟"))
                .setMessage(L.t("حساب فعلی سالم است و برای وصل شدن لازم نیست دوباره ثبت‌نام کنید. ")
                        + L.t("ثبت‌نام دوباره فقط وقتی لازم است که کلادفلر حساب را رد کند.\n\n")
                        + L.t("اگر ادامه دهید: اول مستقیم و بعد از طریق پل‌ها امتحان می‌شود. ")
                        + L.t("تا ثبت‌نام جدید کامل نشود حساب فعلی دست نمی‌خورد."))
                .setPositiveButton(L.t("ثبت‌نام دوباره"), (d, w) -> register(L.t("دکمهٔ «ثبت‌نام دوباره» (حساب قبلی حفظ می‌شود تا موفقیت)")))
                .setNegativeButton(L.t("لغو"), null).show();
    }

    /**
     * v1.5.1: registration over several routes (core "register"): direct with fragmented ClientHello + Chrome TLS,
     * then working bridges that reach abroad (Iranian list included). The core writes a temp
     * file; only on OK it replaces config.json (the previous one is kept as config.prev.json). A failure never
     * touches the existing account.
     */
    private void register(String why) {
        if (busyReg) return;
        busyReg = true;
        final List<String> bl = Bridges.registerSet(this, 4);
        Core.log(L.t("ثبت‌نام در Cloudflare WARP … (علت: ") + why + L.t("؛ مسیرها: مستقیم")
                + (bl.isEmpty() ? "" : " + " + bl.size() + L.t(" پل")) + ")");
        new Thread(() -> {
            final StringBuilder err = new StringBuilder();
            final boolean[] ok = {false};
            final String[] route = {""};
            java.io.File tmp = new java.io.File(getFilesDir(), "config.new.json");
            try {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
                List<String> args = new ArrayList<>();
                args.add("register"); args.add("-c"); args.add(tmp.getAbsolutePath());
                args.addAll(Core.dpiArgs(this));
                args.add("-t"); args.add("20s");
                if (!bl.isEmpty()) { args.add("-bridges"); args.add(TextUtils.join(",", bl)); }
                Process p = Core.start(this, args.toArray(new String[0]));
                Core.pump(p, line -> {
                    if (line.equals("OK")) ok[0] = true;
                    else if (line.startsWith("ROUTE ")) route[0] = line.substring(6).trim();
                    else if (line.startsWith("ERR")) err.append(line.substring(3).trim());
                    if (!line.startsWith("ROUTE ")) Core.log(line);
                });
                if (ok[0] && tmp.length() > 10) {
                    java.io.File cur = Core.cfg(this), prev = new java.io.File(getFilesDir(), "config.prev.json");
                    if (cur.length() > 10) {
                        //noinspection ResultOfMethodCallIgnored
                        prev.delete();
                        if (!cur.renameTo(prev)) Core.log(L.t("پشتیبان کانفیگ قبلی ساخته نشد"));
                    }
                    if (!tmp.renameTo(cur)) { ok[0] = false; err.append("rename failed"); if (prev.exists()) prev.renameTo(cur); }
                } else ok[0] = false;
            } catch (Exception e) {
                err.append(e.getMessage());
            } finally {
                if (!ok[0]) //noinspection ResultOfMethodCallIgnored
                    tmp.delete();
            }
            ui.post(() -> {
                busyReg = false;
                if (ok[0]) {
                    Toast.makeText(this, L.t("ثبت‌نام موفق بود") + (route[0].isEmpty() ? "" : " (" + route[0] + ")"), Toast.LENGTH_LONG).show();
                } else {
                    boolean had = Core.hasConfig(this);
                    if (had) Core.log(L.t("ثبت‌نام ناموفق بود؛ حساب WARP قبلی سالم و دست‌نخورده است"));
                    new AlertDialog.Builder(this).setTitle(L.t("ثبت‌نام ناموفق"))
                            .setMessage((had ? L.t("حساب WARP فعلی شما حفظ شد و همچنان قابل استفاده است.\n\n") : "")
                                    + L.t("API کلادفلر (api.cloudflareclient.com) از هیچ مسیری در دسترس نبود ")
                                    + L.t("(مستقیم") + (bl.isEmpty() ? "" : L.t("، ") + bl.size() + L.t(" پل")) + ").\n"
                                    + (bl.isEmpty() ? L.t("پیشنهاد: در صفحهٔ «پل» پل‌ها را تست کنید و دوباره امتحان کنید.\n") : "")
                                    + L.t("یا یک config.json از usque (ساخته‌شده در جای دیگر) وارد کنید.\n\n") + err)
                            .setPositiveButton(L.t("وارد کردن کانفیگ"), (d, w) -> showImport())
                            .setNegativeButton(L.t("بستن"), null).show();
                }
                refresh();
            });
        }, "o76-reg").start();
    }

    private void showImport() {
        final EditText et = new EditText(this);
        et.setHint("{ \"private_key\": ... }");
        et.setMinLines(5);
        et.setTextSize(12);
        et.setTextDirection(View.TEXT_DIRECTION_LTR);
        new AlertDialog.Builder(this).setTitle(L.t("وارد کردن config.json (فرمت usque)"))
                .setMessage(L.t("متن کانفیگ را اینجا بچسبانید یا فایل را انتخاب کنید."))
                .setView(et)
                .setPositiveButton(L.t("ذخیره"), (d, w) -> {
                    String e = Core.importConfig(this, et.getText().toString());
                    Toast.makeText(this, e == null ? L.t("کانفیگ ذخیره شد") : e, Toast.LENGTH_LONG).show();
                    refresh();
                })
                .setNeutralButton(L.t("انتخاب فایل"), (d, w) -> {
                    Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                    i.addCategory(Intent.CATEGORY_OPENABLE);
                    i.setType("*/*");
                    startActivityForResult(i, REQ_FILE);
                })
                .setNegativeButton(L.t("لغو"), null).show();
    }

    private void importFromUri(Uri u) {
        try (InputStream in = getContentResolver().openInputStream(u)) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0 && bo.size() < 1 << 20) bo.write(buf, 0, n);
            String e = Core.importConfig(this, new String(bo.toByteArray(), StandardCharsets.UTF_8));
            Toast.makeText(this, e == null ? L.t("کانفیگ ذخیره شد") : e, Toast.LENGTH_LONG).show();
        } catch (Exception ex) {
            Toast.makeText(this, L.t("خطا در خواندن فایل: ") + ex.getMessage(), Toast.LENGTH_LONG).show();
        }
        refresh();
    }

    // ------------------------------------------------------------ shared UI helpers (used by all screens)
    /** Small UI kit shared by the activities: tinted vector icons, icon buttons, bounded nested-scroll boxes. */
    static final class Ui {
        private Ui() { }

        // v1.5.1 — one set of sizes for every screen (see README "UI rules")
        static final int ICON_BTN = 20;      // icon inside a text button
        static final int ICON_ROW = 18;      // icon in list rows / labels / inline text
        static final int ICON_HEADER = 24;   // icon inside a square icon-only button
        static final int ICON_SQ = 44;       // icon-only button: square side
        static final int GAP = 8;            // icon <-> text
        static final int ROW_H = 48;         // text button height
        static final int MODE_H = 52;        // mode / choice button height (icon above label)
        static final int MARGIN = 4;         // around every button in a row
        static final int RADIUS = 12;

        static int dp(Context c, float v) {
            return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, c.getResources().getDisplayMetrics());
        }

        /** An outline vector icon (res/drawable/ic_*.xml, 24x24 viewport) tinted to {@code color}, bounds sizeDp x sizeDp. */
        static Drawable icon(Context c, int res, int color, int sizeDp) {
            Drawable d = c.getDrawable(res).mutate();
            d.setTint(color);
            int s = dp(c, sizeDp);
            d.setBounds(0, 0, s, s);
            return d;
        }

        /**
         * Button whose icon sits right next to its label (start side, or above it when {@code vertical}) and whose
         * icon+label block is centred as one unit, so the icon-text gap is the same on every button. The label is
         * always one line: it shrinks (down to 10sp) to fit and is ellipsized only below that.
         */
        static final class IconBtn extends Button {
            int iconRes, iconColor, iconDp = ICON_BTN;
            boolean vertical;
            float baseSp = 14;
            private int lastW = -1, lastH = -1;
            private CharSequence lastText;

            IconBtn(Context c) {
                super(c);
                setAllCaps(false);
                setSingleLine(true);
                setMaxLines(1);
                setEllipsize(TextUtils.TruncateAt.END);
                setGravity(Gravity.CENTER);
                setMinHeight(0);
                setMinimumHeight(0);
                setMinWidth(0);
                setMinimumWidth(0);
                setStateListAnimator(null);
                setIncludeFontPadding(false);
                setCompoundDrawablePadding(dp(c, GAP));
            }

            void setIconRes(int res, int color) {
                iconRes = res;
                iconColor = color;
                applyIcon();
                lastW = -1;
                requestLayout();
                invalidate();
            }

            void setBaseSp(float sp) {
                baseSp = sp;
                setTextSize(sp);
                lastW = -1;
                requestLayout();
            }

            private void applyIcon() {
                Drawable d = iconRes == 0 ? null : icon(getContext(), iconRes, iconColor, iconDp);
                if (vertical) setCompoundDrawablesRelative(null, d, null, null);
                else setCompoundDrawablesRelative(d, null, null, null);
            }

            @Override
            public void setText(CharSequence text, BufferType type) {
                super.setText(text, type);
                lastW = -1;
            }

            @Override
            protected void onMeasure(int wSpec, int hSpec) {
                int w = MeasureSpec.getSize(wSpec), h = MeasureSpec.getSize(hSpec);
                boolean exactW = MeasureSpec.getMode(wSpec) == MeasureSpec.EXACTLY;
                boolean exactH = MeasureSpec.getMode(hSpec) == MeasureSpec.EXACTLY;
                if (exactW && (w != lastW || h != lastH || !TextUtils.equals(getText(), lastText))) {
                    lastW = w;
                    lastH = h;
                    lastText = getText();
                    fit(w, exactH ? h : -1);
                } else if (!exactW && lastW != -2) { // wrap_content (e.g. choice chips in a scroller): fixed side padding
                    lastW = -2;
                    setPaddingRelative(dp(getContext(), 14), 0, dp(getContext(), 14), 0);
                }
                super.onMeasure(wSpec, hSpec);
            }

            /** Picks the text size and the padding that centre icon+label as one block. */
            private void fit(int w, int h) {
                Context c = getContext();
                int minPad = dp(c, 8), gap = iconRes == 0 ? 0 : dp(c, GAP), ic = iconRes == 0 ? 0 : dp(c, iconDp);
                String t = getText() == null ? "" : getText().toString();
                float sp = baseSp;
                android.text.TextPaint p = new android.text.TextPaint(getPaint());
                int avail = vertical ? w - 2 * minPad : w - 2 * minPad - ic - gap;
                while (true) {
                    p.setTextSize(TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, sp, c.getResources().getDisplayMetrics()));
                    if (p.measureText(t) <= avail || sp <= 10f) break;
                    sp -= 0.5f;
                }
                super.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
                float tw = Math.min(avail, p.measureText(t));
                if (vertical) {
                    int lineH = (int) Math.ceil(p.getFontMetrics().descent - p.getFontMetrics().ascent);
                    int content = ic + gap + lineH;
                    int vp = h > 0 ? Math.max(dp(c, 2), (h - content) / 2) : dp(c, 6);
                    setPadding(minPad, vp, minPad, vp);
                } else {
                    int hp = Math.max(minPad, (int) ((w - (ic + gap + tw)) / 2f));
                    setPaddingRelative(hp, 0, hp, 0);
                }
            }
        }

        /** Start-side icon (right in RTL) on any TextView; IconBtn keeps its own size, orientation and centring. */
        static void setIcon(TextView t, int res, int color) {
            if (t instanceof IconBtn) { ((IconBtn) t).setIconRes(res, color); return; }
            t.setCompoundDrawablesRelative(icon(t.getContext(), res, color, ICON_ROW), null, null, null);
            t.setCompoundDrawablePadding(dp(t.getContext(), GAP));
            t.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
        }

        static GradientDrawable round(int fill, int stroke, float radiusPx, int strokePx) {
            GradientDrawable g = new GradientDrawable();
            g.setColor(fill);
            g.setCornerRadius(radiusPx);
            if (stroke != 0) g.setStroke(strokePx, stroke);
            return g;
        }

        /** Filled rounded button with a white icon and a ripple. */
        static Button button(Context c, String s, int icon, int accent) {
            IconBtn b = new IconBtn(c);
            b.setText(s);
            b.setTextColor(Color.WHITE);
            b.setBaseSp(14);
            b.setBackground(new RippleDrawable(ColorStateList.valueOf(0x40FFFFFF), round(accent, accent, dp(c, RADIUS), dp(c, 1)), null));
            if (icon != 0) b.setIconRes(icon, Color.WHITE);
            return b;
        }

        /** Mode / choice button: icon above a one-line label; selected and unselected differ only in fill and text colour. */
        static IconBtn choiceButton(Context c, String s, int icon, int accent, boolean selected) {
            IconBtn b = new IconBtn(c);
            b.vertical = icon != 0;
            b.iconRes = icon;
            b.setText(s);
            b.setBaseSp(13);
            styleChoice(b, accent, selected);
            return b;
        }

        static void styleChoice(IconBtn b, int accent, boolean selected) {
            Context c = b.getContext();
            int fg = selected ? Color.WHITE : accent;
            // same stroke width, radius, padding and typeface in both states, so size and label width never change
            b.setBackground(new RippleDrawable(ColorStateList.valueOf(0x30000000),
                    round(selected ? accent : Color.WHITE, accent, dp(c, RADIUS), dp(c, 1)), null));
            b.setTextColor(fg);
            b.setTypeface(Typeface.DEFAULT_BOLD);
            b.iconColor = fg;
            b.applyIcon();
            b.setSelected(selected);
        }

        /**
         * A row of equal buttons: same weight, same fixed height, same margins; never baseline-aligned (a two-line or
         * bold label used to push its neighbours up/down) and never clipping its children.
         */
        static LinearLayout row(Context c, int heightDp, View... vs) {
            LinearLayout r = new LinearLayout(c);
            r.setOrientation(LinearLayout.HORIZONTAL);
            r.setBaselineAligned(false);
            r.setGravity(Gravity.CENTER_VERTICAL);
            r.setClipChildren(false);
            r.setClipToPadding(false);
            for (View v : vs) {
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(c, heightDp), 1f);
                lp.setMargins(dp(c, MARGIN), dp(c, MARGIN), dp(c, MARGIN), dp(c, MARGIN));
                lp.gravity = Gravity.CENTER_VERTICAL;
                r.addView(v, lp);
            }
            return r;
        }

        static LinearLayout row(Context c, View... vs) {
            return row(c, ROW_H, vs);
        }

        /** 44dp square icon-only button (light card, 24dp tinted icon, centred); description shown on long press. */
        static ImageButton iconButton(Context c, int res, int color, String desc, View.OnClickListener l) {
            ImageButton b = new ImageButton(c);
            b.setImageDrawable(icon(c, res, color, ICON_HEADER));
            b.setScaleType(android.widget.ImageView.ScaleType.CENTER);
            b.setPadding(0, 0, 0, 0);
            b.setMinimumWidth(0);
            b.setMinimumHeight(0);
            b.setContentDescription(desc);
            b.setBackground(new RippleDrawable(ColorStateList.valueOf(0x30000000),
                    round(Color.rgb(241, 245, 249), Color.rgb(226, 232, 240), dp(c, 10), dp(c, 1)), null));
            b.setOnClickListener(l);
            b.setOnLongClickListener(v -> { Toast.makeText(c, desc, Toast.LENGTH_SHORT).show(); return true; });
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(c, ICON_SQ), dp(c, ICON_SQ));
            lp.setMargins(dp(c, MARGIN), 0, dp(c, MARGIN), 0);
            lp.gravity = Gravity.CENTER_VERTICAL;
            b.setLayoutParams(lp);
            return b;
        }

        /** setText only when the text actually changed (avoids relayout + scroll jumps from the 1 s tick). */
        static void setText(TextView t, CharSequence s) {
            if (!TextUtils.equals(t.getText(), s)) t.setText(s);
        }

        /** An image span centred on the text line (ImageSpan.ALIGN_CENTER needs API 29; minSdk is 24). */
        static final class CenteredIconSpan extends android.text.style.ReplacementSpan {
            final Drawable d;

            CenteredIconSpan(Drawable d) { this.d = d; }

            @Override
            public int getSize(android.graphics.Paint p, CharSequence t, int s, int e, android.graphics.Paint.FontMetricsInt fm) {
                android.graphics.Rect r = d.getBounds();
                if (fm != null) {
                    android.graphics.Paint.FontMetricsInt pf = p.getFontMetricsInt();
                    int textH = pf.descent - pf.ascent, ih = r.height();
                    if (ih > textH) { // grow the line symmetrically so the icon is never clipped
                        int extra = (ih - textH + 1) / 2;
                        fm.ascent = pf.ascent - extra;
                        fm.descent = pf.descent + extra;
                    } else {
                        fm.ascent = pf.ascent;
                        fm.descent = pf.descent;
                    }
                    fm.top = fm.ascent;
                    fm.bottom = fm.descent;
                }
                return r.right;
            }

            @Override
            public void draw(android.graphics.Canvas cv, CharSequence t, int s, int e, float x, int top, int y, int bottom, android.graphics.Paint p) {
                android.graphics.Paint.FontMetricsInt pf = p.getFontMetricsInt();
                int centre = y + (pf.descent + pf.ascent) / 2;
                cv.save();
                cv.translate(x, centre - d.getBounds().height() / 2f);
                d.draw(cv);
                cv.restore();
            }
        }

        /** "[icon] text" as a spannable (used instead of emoji like 📌 / 🔑 in list rows); icon 18dp, centred on the line. */
        static CharSequence withIcon(Context c, int res, int color, String s) {
            SpannableStringBuilder sb = new SpannableStringBuilder("  " + s);
            sb.setSpan(new CenteredIconSpan(icon(c, res, color, ICON_ROW)), 0, 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            return sb;
        }

        /** ScrollView whose height is capped at maxPx (wraps content up to that). */
        static final class BoundedScrollView extends ScrollView {
            final int maxPx;

            BoundedScrollView(Context c, int maxPx) {
                super(c);
                this.maxPx = maxPx;
            }

            @Override
            protected void onMeasure(int w, int h) {
                int mode = MeasureSpec.getMode(h), size = MeasureSpec.getSize(h);
                if (mode == MeasureSpec.UNSPECIFIED || size > maxPx) h = MeasureSpec.makeMeasureSpec(maxPx, MeasureSpec.AT_MOST);
                super.onMeasure(w, h);
            }
        }

        /** A rounded card that scrolls its content on its own (max height maxDp), chaining to the outer scroll at its ends. */
        static BoundedScrollView boundedBox(Context c, View content, int maxDp) {
            BoundedScrollView s = new BoundedScrollView(c, dp(c, maxDp));
            s.setNestedScrollingEnabled(true);
            s.setDescendantFocusability(ViewGroup.FOCUS_BLOCK_DESCENDANTS);
            s.setScrollBarStyle(View.SCROLLBARS_INSIDE_INSET);
            s.setPadding(dp(c, 10), dp(c, 6), dp(c, 10), dp(c, 6));
            s.setClipToPadding(false);
            s.setBackground(round(Color.WHITE, Color.rgb(226, 232, 240), dp(c, 12), dp(c, 1)));
            s.addView(content, new ScrollView.LayoutParams(-1, -2));
            return s;
        }
    }
}
