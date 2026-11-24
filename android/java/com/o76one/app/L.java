package com.o76one.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.view.View;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.HashMap;

/** v1.8.1 UI language: Persian (source strings), English, Simplified Chinese. Tables in assets/i18n.json. */
public final class L {
    public static final String[] CODES = {"fa", "en", "zh"};
    public static final String[] FLAGS = {"\uD83C\uDDEE\uD83C\uDDF7", "\uD83C\uDDEC\uD83C\uDDE7", "\uD83C\uDDE8\uD83C\uDDF3"};
    public static final String[] NAMES = {"فارسی", "English", "简体中文"};
    private static volatile String lang = "fa";
    private static volatile HashMap<String, String> map = new HashMap<>();
    private static Context app;

    private L() { }

    private static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("o76lang", Context.MODE_PRIVATE);
    }

    public static synchronized void init(Context c) {
        if (app != null) return;
        app = c.getApplicationContext();
        load(prefs(app).getString("lang", "fa"));
    }

    public static synchronized void set(Context c, String code) {
        if (app == null) app = c.getApplicationContext();
        prefs(app).edit().putString("lang", code).apply();
        load(code);
    }

    public static String lang() { return lang; }

    public static int index() {
        for (int i = 0; i < CODES.length; i++) if (CODES[i].equals(lang)) return i;
        return 0;
    }

    private static void load(String code) {
        HashMap<String, String> m = new HashMap<>();
        int col = "en".equals(code) ? 0 : "zh".equals(code) ? 1 : -1;
        if (col >= 0 && app != null) {
            try (InputStream in = app.getAssets().open("i18n.json")) {
                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                byte[] b = new byte[16384];
                int n;
                while ((n = in.read(b)) > 0) bo.write(b, 0, n);
                JSONObject o = new JSONObject(bo.toString("UTF-8"));
                java.util.Iterator<String> it = o.keys();
                while (it.hasNext()) {
                    String k = it.next();
                    JSONArray a = o.getJSONArray(k);
                    m.put(k, a.getString(col));
                }
            } catch (Throwable t) {
                col = -1;
                m.clear();
            }
        }
        map = m;
        lang = col < 0 ? "fa" : code;
    }

    /** translate a Persian source string; unknown strings stay Persian */
    public static String t(String fa) {
        if (fa == null || "fa".equals(lang)) return fa;
        String s = map.get(fa);
        return s == null ? fa : s;
    }

    public static boolean rtl() { return "fa".equals(lang); }

    public static int dir() { return rtl() ? View.LAYOUT_DIRECTION_RTL : View.LAYOUT_DIRECTION_LTR; }

    public static int tdir() { return rtl() ? View.TEXT_DIRECTION_RTL : View.TEXT_DIRECTION_LTR; }
}
