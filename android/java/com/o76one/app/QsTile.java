package com.o76one.app;

import android.annotation.TargetApi;
import android.app.PendingIntent;
import android.content.Intent;
import android.graphics.drawable.Icon;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/** v1.8.6: Quick Settings tile. Tap connects with the last-used mode or disconnects; long-press opens the app
 *  (QS_TILE preference action on MainActivity). Android 7+ only; the manifest entry is ignored below API 24. */
@TargetApi(24)
public class QsTile extends TileService {
    private final Handler h = new Handler(Looper.getMainLooper());
    private boolean listening;
    private final Runnable tick = new Runnable() {
        @Override public void run() {
            if (!listening) return;
            refresh();
            h.postDelayed(this, 1000);
        }
    };

    @Override public void onStartListening() { listening = true; h.removeCallbacks(tick); h.post(tick); }
    @Override public void onStopListening() { listening = false; h.removeCallbacks(tick); }

    @Override public void onClick() {
        int st = O76VpnService.state;
        if (st == O76VpnService.ST_ON || st == O76VpnService.ST_CONNECTING || st == O76VpnService.ST_RECONNECTING) {
            if (!O76VpnService.stopFromOutside()) {
                try { startService(new Intent(this, O76VpnService.class).setAction(O76VpnService.ACTION_STOP)); }
                catch (Exception e) { openApp(); }
            }
        } else {
            Intent prep = null;
            try { prep = VpnService.prepare(this); } catch (Exception ignored) { }
            if (prep != null) { openApp(); return; } // VPN permission must be granted inside the app first
            O76VpnService.state = O76VpnService.ST_CONNECTING;
            O76VpnService.stateMsg = "";
            Intent i = new Intent(this, O76VpnService.class).setAction(O76VpnService.ACTION_CONNECT);
            try {
                if (Build.VERSION.SDK_INT >= 26) startForegroundService(i); else startService(i);
            } catch (Exception e) {
                O76VpnService.state = O76VpnService.ST_OFF;
                openApp();
            }
        }
        refresh();
    }

    private void openApp() {
        Intent i = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        if (Build.VERSION.SDK_INT >= 34) {
            PendingIntent pi = PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE);
            startActivityAndCollapse(pi);
        } else {
            startActivityAndCollapse(i);
        }
    }

    static String modeName(String m) {
        if (Core.MODE_FOX.equals(m)) return "Firefox";
        if (Core.MODE_BRIDGE.equals(m)) return L.t("پل");
        if (Core.MODE_CHAIN.equals(m)) return L.t("کانفیگ+سایفون");
        if (Core.MODE_AETHER.equals(m)) return "Aether";
        if (Core.MODE_WPLUS.equals(m)) return L.t("وارپ+");
        return "WARP";
    }

    private void refresh() {
        Tile t = getQsTile();
        if (t == null) return;
        int st = O76VpnService.state;
        String mode = O76VpnService.modeInUse;
        if (mode == null || mode.isEmpty()) { try { mode = Core.mode(this); } catch (Exception e) { mode = ""; } }
        String sub;
        int s;
        switch (st) {
            case O76VpnService.ST_ON:
                s = Tile.STATE_ACTIVE;
                sub = (O76VpnService.noData ? "⚠ " : L.t("وصل · ")) + modeName(mode);
                break;
            case O76VpnService.ST_CONNECTING:
            case O76VpnService.ST_RECONNECTING:
                s = Tile.STATE_ACTIVE;
                sub = L.t("در حال اتصال…");
                break;
            case O76VpnService.ST_ERROR:
                s = Tile.STATE_INACTIVE;
                sub = L.t("خطا · ") + modeName(mode);
                break;
            default:
                s = Tile.STATE_INACTIVE;
                sub = L.t("قطع · ") + modeName(mode);
        }
        t.setIcon(Icon.createWithResource(this, R.drawable.ic_tile_01));
        t.setLabel("076ONE");
        t.setState(s);
        if (Build.VERSION.SDK_INT >= 29) t.setSubtitle(sub);
        else t.setLabel("076ONE · " + sub);
        t.updateTile();
    }
}
