package com.o76one.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/** v1.7 Firefox mode: sign in with the user's own Firefox account, protocol, location. Persian RTL. */
public class FoxActivity extends Activity {
    private static final int ACCENT = Color.rgb(14, 116, 144);
    private TextView accTv, statusTv;
    private EditText emailEt, passEt;
    private Button loginBtn, logoutBtn;
    private LinearLayout loginBox, locBox;
    private volatile boolean busy;

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

    private EditText field(String hint, int type) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setInputType(type);
        e.setSingleLine(true);
        e.setTextDirection(View.TEXT_DIRECTION_LTR);
        e.setGravity(Gravity.START | Gravity.CENTER_VERTICAL);
        return e;
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

        TextView title = text("Firefox", 24, true);
        title.setGravity(Gravity.CENTER);
        title.setTextColor(ACCENT);
        root.addView(title, new LinearLayout.LayoutParams(-1, -2));
        root.addView(text(L.t("با حساب فایرفاکس خودتان وارد شوید؛ ترافیک از شبکهٔ پراکسی VPN فایرفاکس/موزیلا (HTTP/3 یا HTTP/2 روی ")
                + L.t("سرورهای Fastly) عبور می‌کند — همان مسیری که کلاینت Predator VPN استفاده می‌کند. سهمیهٔ حجم ماهانه مال همان حساب است. ")
                + L.t("UDP عمومی (مثل تماس صوتی برخی برنامه‌ها) پشتیبانی نمی‌شود."), 13, false));

        accTv = text("", 15, true);
        accTv.setPadding(dp(10), dp(8), dp(10), dp(8));
        GradientDrawable g = new GradientDrawable();
        g.setColor(Color.WHITE);
        g.setCornerRadius(dp(8));
        g.setStroke(dp(1), Color.rgb(203, 213, 225));
        accTv.setBackground(g);
        LinearLayout.LayoutParams alp = new LinearLayout.LayoutParams(-1, -2);
        alp.setMargins(0, dp(8), 0, dp(8));
        root.addView(accTv, alp);

        loginBox = new LinearLayout(this);
        loginBox.setOrientation(LinearLayout.VERTICAL);
        root.addView(loginBox, new LinearLayout.LayoutParams(-1, -2));
        emailEt = field(L.t("ایمیل حساب فایرفاکس"), InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS);
        passEt = field(L.t("رمز عبور"), InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        loginBox.addView(emailEt, new LinearLayout.LayoutParams(-1, -2));
        loginBox.addView(passEt, new LinearLayout.LayoutParams(-1, -2));
        loginBtn = MainActivity.Ui.button(this, L.t("ورود"), R.drawable.ic_key, ACCENT);
        loginBtn.setOnClickListener(v -> doLogin());
        loginBox.addView(MainActivity.Ui.row(this, loginBtn));
        loginBox.addView(text(L.t("رمز فقط یک بار برای ورود به سرور فایرفاکس فرستاده می‌شود و روی گوشی ذخیره نمی‌شود؛ فقط توکن ورود ")
                + L.t("(در حافظهٔ خصوصی برنامه) می‌ماند. اگر فایرفاکس کد تأیید ایمیل یا تصویر امنیتی خواست، همین‌جا نشان داده می‌شود."), 12, false));

        logoutBtn = MainActivity.Ui.button(this, L.t("خروج از حساب"), R.drawable.ic_close, Color.rgb(100, 116, 139));
        logoutBtn.setOnClickListener(v -> new Thread(() -> {
            Fox.logout(this);
            runOnUiThread(this::render);
        }).start());
        root.addView(MainActivity.Ui.row(this, logoutBtn));

        statusTv = text("", 13, true);
        statusTv.setTextColor(Color.rgb(154, 52, 18));
        root.addView(statusTv);

        root.addView(text(L.t("پروتکل"), 17, true));
        choices(root, new String[]{Fox.T_AUTO, Fox.T_H3, Fox.T_H2}, new String[]{L.t("خودکار"), "HTTP/3", "HTTP/2"}, Fox.transport(this),
                v -> Fox.setTransport(this, v));
        root.addView(text(L.t("خودکار: اول HTTP/3 (UDP) و اگر بسته بود HTTP/2 (TCP). روی اینترنت‌هایی که UDP بسته است HTTP/2 را انتخاب کنید."), 12, false));

        root.addView(text(L.t("مکان"), 17, true));
        locBox = new LinearLayout(this);
        locBox.setOrientation(LinearLayout.VERTICAL);
        root.addView(locBox, new LinearLayout.LayoutParams(-1, -2));
        Button refresh = MainActivity.Ui.button(this, L.t("به‌روزرسانی فهرست مکان‌ها"), R.drawable.ic_refresh, Color.rgb(100, 116, 139));
        refresh.setOnClickListener(v -> new Thread(() -> {
            runOnUiThread(() -> statusTv.setText(L.t("دریافت فهرست مکان‌ها…")));
            String msg;
            try { msg = Fox.refreshServers(this) + L.t(" مکان دریافت شد"); } catch (Exception e) { msg = L.t("خطا: ") + e.getMessage(); }
            final String m = msg;
            runOnUiThread(() -> { statusTv.setText(m); renderLocations(); });
        }).start());
        root.addView(MainActivity.Ui.row(this, refresh));

        CheckBox rec = new CheckBox(this);
        rec.setText(L.t("بازیابی ورود از طریق رله‌های عمومی (اختیاری)"));
        rec.setTypeface(Typeface.DEFAULT_BOLD);
        rec.setTextSize(15);
        rec.setChecked(Fox.recovery(this));
        rec.setOnCheckedChangeListener((v, on) -> Fox.setRecovery(this, on));
        root.addView(rec);
        root.addView(text(L.t("فقط وقتی سرور حساب فایرفاکس روی اینترنت شما باز نمی‌شود: درخواست‌های ورود و تمدید توکن از طریق ")
                + L.t("کانفیگ‌های عمومی رایگان فرستاده می‌شوند (TLS تا سرور فایرفاکس سرتاسری است). پیش‌فرض خاموش."), 12, false));

        Button use = MainActivity.Ui.button(this, L.t("استفاده از حالت Firefox"), R.drawable.ic_check, ACCENT);
        use.setOnClickListener(v -> {
            Core.setMode(this, Core.MODE_FOX);
            Core.log(L.t("حالت اتصال: Firefox"));
            boolean active = O76VpnService.state == O76VpnService.ST_ON || O76VpnService.state == O76VpnService.ST_CONNECTING
                    || O76VpnService.state == O76VpnService.ST_RECONNECTING;
            Toast.makeText(this, active ? L.t("حالت Firefox — برای اعمال، یک بار قطع و وصل کنید") : L.t("حالت Firefox انتخاب شد"), Toast.LENGTH_LONG).show();
            finish();
        });
        root.addView(MainActivity.Ui.row(this, use));

        TextView lic = text(L.t("هستهٔ این حالت: Predator VPN v") + Fox.VERSION + L.t(" (erfan-tahvilian) — مجوز GPL-3.0 — ") + Fox.REPO
                + L.t("\nوابسته به موزیلا نیست. (متن مجوز: تنظیمات ← درباره)"), 11, false);
        lic.setTextColor(Color.rgb(100, 116, 139));
        root.addView(lic);

        setContentView(sv);
        render();
    }

    private void render() {
        boolean in = Fox.signedIn(this);
        accTv.setText(in ? L.t("وارد شده: ") + Fox.email(this) : L.t("وارد نشده‌اید"));
        loginBox.setVisibility(in ? View.GONE : View.VISIBLE);
        logoutBtn.setVisibility(in ? View.VISIBLE : View.GONE);
        loginBtn.setEnabled(!busy);
        loginBtn.setAlpha(busy ? 0.5f : 1f);
        renderLocations();
    }

    private void renderLocations() {
        locBox.removeAllViews();
        List<String> ids = new ArrayList<>(), labels = new ArrayList<>();
        ids.add("REC");
        labels.add(L.t("پیشنهادی"));
        for (String l : Fox.servers(this).split("\n")) {
            String[] s = l.split("\\|", -1);
            if (s.length < 3 || "REC".equals(s[1])) continue;
            ids.add(s[0]);
            labels.add(s[2] + (s.length > 3 && !s[3].isEmpty() ? " · " + s[3] : ""));
        }
        String cur = Fox.server(this);
        if (!ids.contains(cur)) cur = "REC";
        choices(locBox, ids.toArray(new String[0]), labels.toArray(new String[0]), cur, v -> Fox.setServer(this, v));
        if (ids.size() == 1) locBox.addView(text(L.t("فهرست مکان‌ها هنوز دریافت نشده؛ «پیشنهادی» نزدیک‌ترین سرور را خودکار انتخاب می‌کند."), 12, false));
    }

    private void doLogin() {
        final String email = emailEt.getText().toString().trim();
        final String pass = passEt.getText().toString();
        if (email.isEmpty() || pass.isEmpty()) {
            Toast.makeText(this, L.t("ایمیل و رمز را وارد کنید"), Toast.LENGTH_SHORT).show();
            return;
        }
        long until = getSharedPreferences("fox_lock", MODE_PRIVATE).getLong("until", 0);
        if (until > System.currentTimeMillis()) {
            statusTv.setText(lockMsg(until));
            return;
        }
        busy = true;
        statusTv.setText(L.t("ورود به حساب فایرفاکس… (ممکن است تا یک دقیقه طول بکشد)"));
        render();
        new Thread(() -> {
            String err = Fox.login(this, email, pass, new Fox.LoginUi() {
                public String askCode(String method) {
                    String msg = "totp-2fa".equals(method) ? L.t("کد ۶ رقمی برنامهٔ احراز هویت (Authenticator) را وارد کنید")
                            : L.t("فایرفاکس یک کد تأیید به ایمیل ") + email + L.t(" فرستاد؛ آن را وارد کنید");
                    return ask(L.t("کد تأیید"), msg, null);
                }

                int captchas = 0;
                public String askCaptcha(File image) {
                    captchas++;
                    String m = L.t("نوشتهٔ داخل تصویر را با حروف و اعداد انگلیسی وارد کنید");
                    if (captchas > 1) m = L.t("جواب قبلی پذیرفته نشد؛ این تصویر جدید است.") + "\n" + m;
                    return ask(L.t("تصویر امنیتی"), m, image);
                }

                public void status(String s) { runOnUiThread(() -> statusTv.setText(s)); }
            });
            busy = false;
            final String shown = rateLimited(err);
            runOnUiThread(() -> {
                passEt.setText("");
                statusTv.setText(err == null ? L.t("ورود موفق ✓") : shown != null ? shown : L.t("خطا: ") + err);
                render();
            });
        }).start();
    }

    /** Mozilla "too many requests": remember the unlock time and block retries until then. */
    private String rateLimited(String err) {
        if (err == null || !err.toLowerCase(java.util.Locale.ROOT).contains("too many")) return null;
        long secs = 15 * 60;
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("retryAfter=(\\d+)").matcher(err);
        if (m.find()) { try { secs = Long.parseLong(m.group(1)); } catch (Exception ignored) {} }
        long until = System.currentTimeMillis() + secs * 1000L;
        getSharedPreferences("fox_lock", MODE_PRIVATE).edit().putLong("until", until).apply();
        return lockMsg(until);
    }

    private String lockMsg(long until) {
        String t = new java.text.SimpleDateFormat("HH:mm", java.util.Locale.US).format(new java.util.Date(until));
        long min = Math.max(1, (until - System.currentTimeMillis() + 59999) / 60000);
        return L.t("موزیلا به‌خاطر تلاش‌های زیاد ورود را موقتاً بسته است. تا ساعت ") + t
                + L.t(" (حدود ") + min + L.t(" دقیقه) دوباره تلاش نکنید؛ هر تلاش زودتر قفل را طولانی‌تر می‌کند.");
    }

    /** blocking dialog from a worker thread; null = cancelled */
    private String ask(String title, String msg, File image) {
        final CountDownLatch done = new CountDownLatch(1);
        final AtomicReference<String> res = new AtomicReference<>();
        runOnUiThread(() -> {
            LinearLayout box = new LinearLayout(this);
            box.setOrientation(LinearLayout.VERTICAL);
            box.setPadding(dp(16), dp(8), dp(16), dp(8));
            TextView t = text(msg, 14, false);
            box.addView(t);
            if (image != null) {
                Bitmap bm = BitmapFactory.decodeFile(image.getAbsolutePath());
                if (bm != null) {
                    ImageView iv = new ImageView(this);
                    iv.setImageBitmap(bm);
                    iv.setAdjustViewBounds(true);
                    box.addView(iv, new LinearLayout.LayoutParams(-1, -2));
                }
            }
            EditText e = field("", image == null ? InputType.TYPE_CLASS_NUMBER : InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            box.addView(e, new LinearLayout.LayoutParams(-1, -2));
            new AlertDialog.Builder(this).setTitle(title).setView(box).setCancelable(false)
                    .setPositiveButton(L.t("تأیید"), (d, w) -> { res.set(e.getText().toString()); done.countDown(); })
                    .setNegativeButton(L.t("لغو"), (d, w) -> done.countDown())
                    .show();
        });
        try { done.await(); } catch (InterruptedException ignored) { }
        return res.get();
    }

    @Override
    protected void onResume() {
        super.onResume();
        render();
    }
}
