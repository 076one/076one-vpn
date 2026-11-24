package com.o76one.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import org.json.JSONObject;
import java.util.List;

import java.io.File;
import java.io.FileDescriptor;
import java.io.OutputStream;

/**
 * VpnService: creates the TUN interface and hands its fd to the Go core (MASQUE, HTTP/3 first with
 * automatic HTTP/2 fallback). Picks the lowest-latency healthy server unless one is pinned, and switches
 * server (plus a background re-scan) when the current one fails twice.
 */
public class O76VpnService extends VpnService {
    public static final String ACTION_CONNECT = "com.o76one.app.CONNECT";
    public static final String ACTION_STOP = "com.o76one.app.STOP";

    public static final int ST_OFF = 0, ST_CONNECTING = 1, ST_ON = 2, ST_RECONNECTING = 3, ST_ERROR = 4;

    // shared state read by MainActivity (same process)
    public static volatile int state = ST_OFF;
    public static volatile String stateMsg = "";
    public static volatile String endpoint = "";   // ip:port in use
    public static volatile String proto = "";      // "h3" | "h2" in use
    public static volatile String sniUsed = "";
    public static volatile int switches;
    public static volatile long rxTotal, txTotal;
    public static volatile double downBps, upBps;
    /** real in-tunnel round trip (DNS probe through the tunnel), ms; 0 = not measured yet */
    public static volatile long realRtt;
    /** true while the tunnel is "up" but no data comes back */
    public static volatile boolean noData;
    /** v1.3: bridge (upstream proxy) in use, "scheme://ip:port" without credentials; "" = direct */
    public static volatile String bridgeInUse = "";
    /** v1.4: connection mode of the running session ("warp" | "bridge" | "chain" | "aether" | "fox" | "wplus") */
    public static volatile String modeInUse = "";
    /** v1.6 Aether mode: exit reported by the Aether core ("104.28.x.x, US via PDX, …"); "" otherwise */
    public static volatile String aetherExit = "";
    /** v1.7 Firefox mode: remaining monthly data as the service reports it */
    public static volatile String foxQuota = "";
    /** v1.4: harmless "Hop Limit/TTL too small" drops counted by the core (not logged line by line) */
    public static volatile long ttlDrops;

    /** v1.5: the running service (for bridgesUpdated); null when none */
    private static volatile O76VpnService instance;

    private ParcelFileDescriptor tun;
    private Process proc;
    /** v1.6: the running Aether core (Aether mode only) */
    private volatile Aether.Run aRun;
    /** v1.7: the running Firefox core (Firefox mode only) */
    private volatile Fox.Run fRun;
    /** v1.8: the running warp-plus core (وارپ+ mode only) */
    private volatile WarpPlus.Run wRun;
    /** v1.8.2: the running Config + Psiphon core (libchain) */
    private volatile Chain.Run cRun;
    private int cRestarts;
    private volatile long cUpAt, cRestartAt;
    // v1.8.3 Config + Psiphon recovery: never give up, partial (Psiphon-only) restart first, backoff, failover
    private static final long[] C_BACKOFF = {2000, 5000, 10000, 20000, 30000};
    private volatile int cAttempts;        // full (re)starts in a row without data (backoff index, "reconnecting #n")
    private volatile int cFailStreak;      // failed recoveries in a row on the current config (2 -> next config)
    private volatile boolean cGotData;     // this chain session passed data (STATE up)
    private volatile boolean cRecovering;  // a partial recovery is running
    private volatile int cPartialNoUp;     // partial recoveries reported OK but no data since
    private volatile int cRecNo;           // partial recoveries this connection
    private final java.util.HashSet<String> cTried = new java.util.HashSet<>(); // configs tried in this failover round
    /** v1.8.2: Config + Psiphon stage for the main screen ("" when not in that mode) */
    public static volatile String chainStage = "";
    /** v1.8.4: the running session is "Bridge + Psiphon" (bridge mode, Psiphon through the proxy; libchain -upstream) */
    public static volatile boolean bridgePsi;
    private volatile boolean cBridge;
    private int wRestarts;
    private long wUpAt, wRestartAt;
    private int fRestarts;
    private volatile long fUpAt, fRestartAt;
    // v1.8.5 Firefox: never gives up (backoff 2/5/10/20/30 s), libfpn alone is restarted on the same SOCKS port
    private volatile int fAttempts;        // restarts in a row without data (backoff index, "reconnecting #n")
    private volatile boolean fRecovering;  // a libfpn-only restart is running
    private volatile boolean fFatal;       // signed out / quota used up: reconnecting cannot help
    // v1.8.5 Bridge + Psiphon: switch to a warm standby bridge after a 40 s stall; refused bridges are skipped
    private volatile String bWarmKey = "";
    private volatile long bWarmAt, bWarmMs, bWarmDue;
    private final java.util.HashSet<String> bRefused = new java.util.HashSet<>();
    private volatile boolean cNoDelay;     // next chain start without backoff (bridge switch / refused bridge)
    /** v1.8.5: local SOCKS5 port of the running tunnel (SOCKS-based modes), 0 = none; the updater downloads through it */
    public static volatile int socksPort;
    private volatile long aUpAt, aRestartAt;
    private int aRestarts;
    private volatile boolean stopping;
    private Thread worker;
    private volatile int gen;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? null : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopVpn(L.t("قطع شد"));
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_CONNECT.equals(action)) {
            instance = this;
            stopVpn(null);
            stopping = false;
            final int myGen = ++gen;
            startForegroundCompat();
            worker = new Thread(() -> connect(myGen), "o76-vpn");
            worker.start();
        }
        return START_NOT_STICKY;
    }

    private void startForegroundCompat() {
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE); // (Class) overload is API 23
            Notification.Builder b;
            if (Build.VERSION.SDK_INT >= 26) {
                nm.createNotificationChannel(new NotificationChannel("vpn", "VPN", NotificationManager.IMPORTANCE_LOW));
                b = new Notification.Builder(this, "vpn");
            } else {
                b = new Notification.Builder(this);
            }
            PendingIntent pi = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            b.setContentTitle("076ONE").setContentText(L.t("VPN فعال است"))
                    .setSmallIcon(android.R.drawable.ic_lock_lock).setContentIntent(pi).setOngoing(true);
            startForeground(1, b.build());
        } catch (Exception e) {
            Core.log("notification: " + e);
        }
    }

    private volatile boolean switchReq;
    private volatile String switchWhy = "";

    private void connect(int myGen) {
        state = ST_CONNECTING;
        stateMsg = L.t("در حال انتخاب سرور…");
        endpoint = proto = sniUsed = "";
        switches = 0;
        rxTotal = txTotal = 0;
        downBps = upBps = 0;
        realRtt = 0;
        noData = false;
        bridgeInUse = "";
        ttlDrops = 0;
        final String mode = Core.mode(this);
        modeInUse = mode;
        // v1.8.4: Bridge + Psiphon runs on the Config + Psiphon machinery (libchain, svpn -chain, no IPv6, partial
        // Psiphon restart, backoff, failover after 2 failed recoveries) with a bridge proxy instead of a config
        final boolean viaBridgePsi = Core.MODE_BRIDGE.equals(mode) && Bridges.viaPsiphon(this);
        final boolean viaChain = Core.MODE_CHAIN.equals(mode) || viaBridgePsi;
        cBridge = viaBridgePsi;
        bridgePsi = viaBridgePsi;
        final boolean viaAether = Core.MODE_AETHER.equals(mode);
        final boolean viaFox = Core.MODE_FOX.equals(mode);
        final boolean viaWp = Core.MODE_WPLUS.equals(mode);
        final boolean viaBridge = !viaChain && !viaAether && !viaFox && !viaWp && Bridges.enabled(this);
        aetherExit = "";
        foxQuota = "";
        aRestarts = 0;
        fRestarts = 0;
        fAttempts = 0;
        fRecovering = false;
        fFatal = false;
        bWarmKey = "";
        bWarmAt = bWarmMs = bWarmDue = 0;
        synchronized (bRefused) { bRefused.clear(); }
        cNoDelay = false;
        socksPort = 0;
        wRestarts = 0;
        cRestarts = 0;
        cAttempts = 0;
        cFailStreak = 0;
        cGotData = false;
        cRecovering = false;
        cPartialNoUp = 0;
        cRecNo = 0;
        synchronized (cTried) { cTried.clear(); }
        if (viaChain) { Chain.resetSession(); Bridges.resetSession(); }
        chainStage = "";
        try {
            String v4, v6;
            if (viaChain) {
                // v1.8.3: no IPv6 address/route in Config + Psiphon mode. Psiphon refuses IPv6 destinations (SOCKS
                // reply 5) after a round trip, so apps stalled on v6 before falling back. With no IPv6 address the
                // system blocks IPv6 for VPN apps at once (VpnService.Builder.allowFamily docs, API 21+), so they
                // use IPv4 immediately; svpn -chain also RSTs any v6 flow and answers AAAA with no records.
                v4 = "10.76.0.2";
                v6 = "";
                Core.log("WLOG chain: IPv6 not routed (apps use IPv4 at once)");
            } else if (viaAether || viaFox || viaWp) {
                // standalone tunnel: no WARP account; the core's userspace stack answers for these addresses
                v4 = "10.76.0.2";
                v6 = "fd00:76::2";
            } else {
                JSONObject cfg = Core.readConfig(this);
                if (cfg == null) throw new Exception(L.t("کانفیگ WARP وجود ندارد؛ اول ثبت‌نام کنید (یا حالت «کانفیگ + سایفون» را انتخاب کنید)"));
                v4 = cfg.optString("ipv4", "172.16.0.2");
                v6 = cfg.optString("ipv6", "");
            }

            Servers.Plan plan;
            if (viaWp) {
                if (!WarpPlus.available(this)) throw new Exception(L.t("هستهٔ وارپ+ روی این گوشی نصب نیست"));
                stateMsg = L.t("وارپ+: ") + WarpPlus.describe(this) + L.t(" — ساخت تونل… (تا ۳ دقیقه)");
                plan = wpPlan(myGen);
            } else if (viaFox) {
                if (!Fox.available(this)) throw new Exception(L.t("هستهٔ Firefox روی این گوشی نصب نیست"));
                stateMsg = L.t("Firefox: ورود با توکن حساب و ساخت تونل… (تا ۲ دقیقه)");
                plan = foxStartLoop(myGen, 0, null); // v1.8.5: retries with backoff; throws when signed out / cancelled
            } else if (viaAether) {
                if (!Aether.available(this)) throw new Exception(L.t("حالت Aether روی این گوشی در دسترس نیست (فقط arm64)"));
                Aether.killStale(this);
                stateMsg = L.t("Aether: جستجوی دروازه و تأیید تونل… (تا ۴ دقیقه)");
                plan = aetherPlan(myGen);
            } else if (viaChain) {
                if (!Chain.available(this)) throw new Exception(L.t("هستهٔ کانفیگ + سایفون روی این گوشی نصب نیست"));
                if (viaBridgePsi) {
                    if (!bridgePsiReady(myGen)) {
                        if (stopping || myGen != gen) return;
                        throw new Exception(L.t("هیچ پل سالمی برای سایفون پیدا نشد — در صفحهٔ «پل» فهرست را به‌روز کنید یا پروکسی بچسبانید و «تست پل‌ها» را بزنید"));
                    }
                } else if (!Chain.configured(this)) throw new Exception(L.t("هیچ کانفیگی ذخیره نشده — در صفحهٔ «کانفیگ + سایفون» لینک بچسبانید"));
                plan = chainStartLoop(myGen); // v1.8.3: retries with backoff + failover; throws only when cancelled
            } else if (viaBridge) {
                stateMsg = L.t("انتخاب پل (پروکسی)…");
                plan = Servers.bridgePlan(this);
                if (stopping || myGen != gen) return;
                if (plan == null) throw new Exception(L.t("هیچ پل (پروکسی) سالمی پیدا نشد — در صفحهٔ «پل» فهرست را به‌روز کنید یا پروکسی بچسبانید، یا پل را خاموش کنید"));
            } else {
                // background re-scan if the saved list is empty or older than 6 h (runs outside the VPN)
                Servers.maybeAutoScan(this, L.t("فهرست خالی یا قدیمی‌تر از ۶ ساعت"));
                if (Core.endpoints(this).isEmpty() && Servers.scanning) {
                    stateMsg = L.t("فهرست سرور خالی است، در حال اسکن…");
                    Servers.awaitScan(45000);
                }
                if (stopping || myGen != gen) return;
                stateMsg = L.t("تست واقعی سرورها…");
                plan = Servers.plan(this);
            }
            if (stopping || myGen != gen) return;

            int mtu = Core.mtu(this);
            Builder b = new Builder();
            b.setSession("076ONE");
            b.setMtu(mtu);
            b.addAddress(v4, 32);
            b.addRoute("0.0.0.0", 0);
            b.addDnsServer("1.1.1.1");
            b.addDnsServer("1.0.0.1");
            if (mtu < 1280 && !v6.isEmpty()) {
                Core.log("MTU " + mtu + L.t(" < 1280: IPv6 غیرفعال شد (IPv6 حداقل 1280 لازم دارد)"));
                v6 = "";
            }
            if (!v6.isEmpty()) {
                try {
                    b.addAddress(v6, 128);
                    b.addRoute("::", 0);
                    b.addDnsServer("2606:4700:4700::1111");
                } catch (Exception e) {
                    Core.log("ipv6 skipped: " + e.getMessage());
                }
            }
            // our own core process must NOT go through the VPN (avoids a loop; scans/probes run direct)
            b.addDisallowedApplication(getPackageName());
            PendingIntent pi = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class),
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            b.setConfigureIntent(pi);
            tun = b.establish();
            if (tun == null) throw new Exception(L.t("اجازهٔ VPN داده نشده"));

            if (viaBridge) startBridgeRetest(myGen);
            if (viaBridgePsi) startBridgeStandby(myGen);
            int code = 0;
            while (!stopping && myGen == gen) {
                switchReq = false;
                code = runCore(plan, myGen);
                if (stopping || myGen != gen) return;
                if (!switchReq && (viaChain || viaFox)) {
                    // v1.8.3 chain / v1.8.5 Firefox: never give up; svpn exiting on its own is one more full restart
                    switchWhy = "svpn exited (code " + code + ")";
                } else if (!switchReq) break; // core died on its own -> error below
                if (viaWp) {
                    switches++;
                    if (wUpAt > wRestartAt + 60_000) wRestarts = 0; // it worked for a while: start counting again
                    wRestarts++;
                    stopWp();
                    Core.log(L.t("وارپ+ کار نکرد (") + switchWhy + L.t(")؛ اتصال دوباره #") + wRestarts);
                    if (wRestarts > 3) {
                        stateMsg = L.t("خطا: وارپ+ پس از ۳ بار اتصال دوباره هم داده رد نکرد — نوع دیگر، کشور یا endpoint دیگری را امتحان کنید");
                        break;
                    }
                    state = ST_RECONNECTING;
                    stateMsg = L.t("وارپ+: اتصال دوباره…");
                    realRtt = 0;
                    noData = false;
                    wRestartAt = System.currentTimeMillis();
                    if (wRestarts >= 2) try { Thread.sleep(3000); } catch (InterruptedException ignored) { }
                    plan = wpPlan(myGen);
                    if (stopping || myGen != gen) return;
                    continue;
                }
                if (viaChain) {
                    // v1.8.3: full chain restart (partial recovery failed, or the core died). Never gives up: backoff
                    // 2/5/10/20/30 s, failover to the next tested config after 2 failed recoveries; the TUN stays.
                    switches++;
                    stopChain();
                    if (!cGotData) cFailStreak++; // this session never passed data
                    cAttempts++;
                    cRestarts++;
                    Core.log(cl("کانفیگ + سایفون کار نکرد (", "پل + سایفون کار نکرد (") + switchWhy + L.t(")؛ اتصال دوباره #") + cAttempts);
                    Core.log("WLOG chain full restart #" + cAttempts + (cBridge ? " (bridge + psiphon), failed recoveries on this bridge: " : " (xray + psiphon), failed recoveries on this config: ") + cFailStreak);
                    state = ST_RECONNECTING;
                    stateMsg = cl("کانفیگ + سایفون: اتصال دوباره #", "پل + سایفون: اتصال دوباره #") + cAttempts + "…";
                    realRtt = 0;
                    noData = false;
                    cRestartAt = System.currentTimeMillis();
                    plan = chainStartLoop(myGen);
                    if (stopping || myGen != gen) return;
                    continue;
                }
                if (viaFox) {
                    // v1.8.5: full restart (svpn died, or a libfpn-only restart failed). Never gives up: backoff
                    // 2/5/10/20/30 s until the user disconnects; only signing out / an empty quota ends it.
                    long w = System.currentTimeMillis() + 5000;
                    while (fRecovering && System.currentTimeMillis() < w) Thread.sleep(100);
                    switches++;
                    fRestarts++;
                    stopFox();
                    if (fFatal) {
                        if (!stateMsg.startsWith(L.t("خطا"))) stateMsg = L.t("خطا: ") + switchWhy;
                        break;
                    }
                    fAttempts++;
                    Core.log(L.t("Firefox کار نکرد (") + switchWhy + L.t(")؛ اتصال دوباره #") + fAttempts);
                    Core.log("WLOG firefox full restart #" + fAttempts + " (libfpn + svpn; tun kept)");
                    state = ST_RECONNECTING;
                    stateMsg = L.t("Firefox: اتصال دوباره #") + fAttempts + "…";
                    realRtt = 0;
                    noData = false;
                    fRestartAt = System.currentTimeMillis();
                    plan = foxStartLoop(myGen, 0, null);
                    if (stopping || myGen != gen) return;
                    continue;
                }
                if (viaAether) {
                    // v1.6: svpn saw no data / Aether stopped validating or exited -> restart the Aether core (rescan)
                    switches++;
                    if (aUpAt > aRestartAt + 60_000) aRestarts = 0; // it worked for a while: start counting again
                    aRestarts++;
                    Aether.Run old = aRun;
                    if (old != null && old.upKey != null) Bridges.markFailedKeyWarp(this, old.upKey);
                    stopAether();
                    Core.log(L.t("Aether کار نکرد (") + switchWhy + L.t(")؛ راه‌اندازی دوباره #") + aRestarts);
                    if (aRestarts > 3) {
                        stateMsg = L.t("خطا: Aether پس از ۳ بار راه‌اندازی دوباره هم داده رد نکرد — پروتکل/SNI دیگر یا حالت دیگری را امتحان کنید");
                        break;
                    }
                    state = ST_RECONNECTING;
                    stateMsg = L.t("Aether: راه‌اندازی دوباره و جستجوی دروازه…");
                    realRtt = 0;
                    noData = false;
                    aRestartAt = System.currentTimeMillis();
                    plan = aetherPlan(myGen); // throws when AetherWatch gives up -> error below
                    if (stopping || myGen != gen) return;
                    continue;
                }
                if (viaBridge) {
                    // current bridge failed: mark it and switch to the next tested bridge (re-test when none left)
                    Bridges.markFailed(this, plan.bridge);
                    switches++;
                    Core.log(L.t("پل فعلی کار نکرد (") + switchWhy + L.t(")؛ تعویض پل #") + switches);
                    state = ST_RECONNECTING;
                    stateMsg = Bridges.workingCount(this) == 0 ? L.t("پل سالم دیگری نمانده؛ تست پروکسی‌های بعدی…") : L.t("تعویض پل…");
                    realRtt = 0;
                    noData = false;
                    Servers.Plan np = Servers.bridgePlan(this);
                    if (stopping || myGen != gen) return;
                    if (np == null) {
                        stateMsg = L.t("خطا: هیچ پل سالمی نمانده — فهرست را به‌روز کنید یا پل را خاموش کنید");
                        break;
                    }
                    plan = np;
                    continue;
                }
                // current server failed: mark it, re-scan in background, switch to the next best
                markCurrentFailed(plan);
                switches++;
                Core.log(L.t("سرور فعلی کار نکرد (") + switchWhy + L.t(")؛ تعویض سرور/SNI #") + switches);
                Servers.startScan(this);
                if (switches % 3 == 0) {
                    stateMsg = L.t("چند سرور ناموفق بود؛ منتظر اسکن تازه…");
                    Servers.awaitScan(60000);
                    if (stopping || myGen != gen) return;
                }
                state = ST_RECONNECTING;
                stateMsg = L.t("تعویض سرور… (تست واقعی)");
                realRtt = 0;
                noData = false;
                plan = Servers.plan(this);
            }
            if (!stopping && myGen == gen) {
                state = ST_ERROR;
                if (!stateMsg.startsWith(L.t("خطا"))) stateMsg = L.t("هسته متوقف شد (کد ") + code + ")";
                Core.log(stateMsg);
                stopAether();
                stopFox();
                stopWp();
                stopChain();
                closeTun();
                stopForeground(true);
                stopSelf();
            }
        } catch (Exception e) {
            if (myGen != gen || stopping) return;
            state = ST_ERROR;
            stateMsg = L.t("خطا: ") + e.getMessage();
            Core.log(stateMsg);
            killProc();
            stopAether();
            stopFox();
            stopWp();
            stopChain();
            closeTun();
            stopForeground(true);
            stopSelf();
        }
    }

    /** v1.6: starts the Aether core and waits (AetherWatch rules, max 240 s) for a validated tunnel + its SOCKS port */
    private Servers.Plan aetherPlan(final int myGen) throws Exception {
        Aether.Run r = Aether.startTunnel(this, () -> stopping || myGen != gen);
        if (stopping || myGen != gen) {
            Aether.stop(r);
            throw new InterruptedException("cancelled");
        }
        aRun = r;
        aetherExit = r.exit;
        Servers.Plan p = new Servers.Plan();
        p.aetherPort = r.port;
        p.bridgeKey = r.upKey;
        return p;
    }

    /** v1.7: starts the Firefox core (own account's token) and waits for its verified tunnel + SOCKS port */
    private Servers.Plan foxPlan(final int myGen, int port, final Process svpn) throws Exception {
        Fox.Run r = Fox.startTunnel(this, () -> stopping || myGen != gen || (svpn != null && proc != svpn), port);
        if (stopping || myGen != gen || (svpn != null && proc != svpn)) {
            Fox.stop(r);
            throw new InterruptedException("cancelled");
        }
        fRun = r;
        aetherExit = r.exit;
        foxQuota = r.quota.isEmpty() ? "" : Fox.quotaFa(r.quota);
        Servers.Plan p = new Servers.Plan();
        p.aetherPort = r.port;
        p.fox = true;
        return p;
    }

    /**
     * v1.8.5 Firefox: starts libfpn, retrying with backoff 2/5/10/20/30 s (shown as "reconnecting #n") until it is
     * up or the user disconnects. Throws at once when the account is signed out or the monthly quota is used up.
     * port > 0 / svpn != null: libfpn-only restart on the same SOCKS port (svpn keeps running); one attempt only.
     */
    private Servers.Plan foxStartLoop(final int myGen, int port, final Process svpn) throws Exception {
        while (true) {
            if (stopping || myGen != gen || (svpn != null && proc != svpn)) throw new InterruptedException("cancelled");
            if (fAttempts > 0) {
                long d = C_BACKOFF[Math.min(fAttempts - 1, C_BACKOFF.length - 1)];
                Core.log("WLOG firefox reconnect #" + fAttempts + " in " + d / 1000 + " s");
                long until = System.currentTimeMillis() + d;
                while (System.currentTimeMillis() < until) {
                    if (stopping || myGen != gen || (svpn != null && proc != svpn)) throw new InterruptedException("cancelled");
                    long left = (until - System.currentTimeMillis() + 999) / 1000;
                    stateMsg = L.t("Firefox: اتصال دوباره #") + fAttempts + L.t(" — ") + left + L.t(" ثانیه دیگر…");
                    Thread.sleep(250);
                }
                stateMsg = L.t("Firefox: اتصال دوباره #") + fAttempts + "…";
            }
            try {
                return foxPlan(myGen, port, svpn);
            } catch (InterruptedException e) {
                throw e;
            } catch (Exception e) {
                if (stopping || myGen != gen) throw new InterruptedException("cancelled");
                if (!Fox.signedIn(this)) { fFatal = true; throw e; }
                Fox.Run fr = fRun;
                if (fr != null && Fox.quotaEmpty(fr.quota)) { fFatal = true; throw e; }
                if (svpn != null) throw e; // libfpn-only restart: the caller falls back to a full restart
                fAttempts++;
                Core.log(L.t("خطا: ") + e.getMessage());
                Core.log("WLOG firefox start failed; reconnect #" + fAttempts);
                if (state == ST_ON) state = ST_RECONNECTING;
            }
        }
    }

    /**
     * v1.8.5 Firefox: svpn saw no data (50 s + 3 failed probes) or libfpn exited. Restart only libfpn on the same
     * SOCKS port after the backoff delay; svpn and the TUN keep running. A failed restart falls back to the full one.
     */
    private void foxRestart(final Process svpn, final int myGen, final String why) {
        synchronized (this) {
            if (fRecovering || switchReq) { Core.log("WLOG firefox " + why + " while restarting; waiting"); return; }
            fRecovering = true;
        }
        new Thread(() -> {
            try {
                Fox.Run old = fRun;
                int port = old != null ? old.port : 0;
                fRun = null; // ends the old watcher
                Fox.stopWait(old);
                fAttempts++;
                switches++;
                fRestarts++;
                state = ST_RECONNECTING;
                realRtt = 0;
                Core.log(L.t("Firefox کار نکرد (") + why + L.t(")؛ اتصال دوباره #") + fAttempts);
                Core.log("WLOG firefox restart #" + fAttempts + ": " + why + " -> libfpn restart on socks port " + port + " (svpn and tun kept)");
                fRestartAt = System.currentTimeMillis();
                foxStartLoop(myGen, port, svpn);
                Fox.Run r = fRun;
                if (r != null) watchFox(r, svpn, myGen);
                stateMsg = L.t("Firefox: دوباره وصل شد، بررسی داده…");
                Core.log("WLOG firefox restart #" + fAttempts + " ok; waiting for data through svpn");
            } catch (InterruptedException e) {
                // disconnected, or svpn ended (the main loop restarts both)
            } catch (Exception e) {
                if (stopping || myGen != gen || proc != svpn) return;
                Core.log(L.t("خطا: ") + e.getMessage());
                Core.log("WLOG firefox restart failed (" + e.getMessage() + ") -> full restart");
                if (fFatal) stateMsg = L.t("خطا: ") + e.getMessage();
                if (!switchReq) {
                    switchReq = true;
                    switchWhy = "FIREFOX: " + e.getMessage();
                    killProc();
                }
            } finally {
                fRecovering = false;
            }
        }, "o76-fox-restart").start();
    }

    /** v1.8: starts warp-plus and waits for its tested tunnel + SOCKS port */
    private Servers.Plan wpPlan(final int myGen) throws Exception {
        WarpPlus.Run r = WarpPlus.startTunnel(this, () -> stopping || myGen != gen);
        if (stopping || myGen != gen) {
            WarpPlus.stop(r);
            throw new InterruptedException("cancelled");
        }
        wRun = r;
        aetherExit = r.exit;
        Servers.Plan p = new Servers.Plan();
        p.aetherPort = r.port;
        p.wp = true;
        return p;
    }

    private void stopWp() {
        WarpPlus.Run r = wRun;
        wRun = null;
        WarpPlus.stop(r);
    }

    /** v1.8.2: starts libchain (Xray config, then Psiphon through it) and waits for its SOCKS port */
    private Servers.Plan chainPlan(final int myGen) throws Exception {
        stateMsg = chainPrefix() + Chain.describe(this);
        final Chain.Run[] holder = {null};
        // show the core's stage (config connecting / Psiphon connecting) while it starts
        final Thread stageT = new Thread(() -> {
            while (!stopping && myGen == gen && state != ST_ON) {
                try { Thread.sleep(500); } catch (InterruptedException e) { return; }
                Chain.Run r = Chain.running;
                if (r != null && !r.stageLabel().isEmpty()) {
                    chainStage = r.stageLabel();
                    if (r.stage != Chain.ST_UP) stateMsg = chainPrefix() + chainStage;
                }
                if (r != null && r.stage == Chain.ST_UP) return;
            }
        }, "o76-chain-stage");
        stageT.start();
        Chain.Run r;
        try {
            r = Chain.startTunnel(this, () -> stopping || myGen != gen, cBridge);
        } finally {
            stageT.interrupt();
        }
        if (stopping || myGen != gen) {
            Chain.stop(r);
            throw new InterruptedException("cancelled");
        }
        cRun = r;
        aetherExit = r.exit;
        chainStage = r.stageLabel();
        cGotData = false;
        cPartialNoUp = 0;
        synchronized (cTried) { cTried.add(cBridge ? Bridges.addrOf(r.bridgeKey) : r.link); }
        Servers.Plan p = new Servers.Plan();
        p.aetherPort = r.port;
        p.chain = true;
        if (cBridge) p.bridgeKey = r.bridgeKey; // shown as the bridge in use; marked ok once data flows
        return p;
    }

    /** v1.8.4: "کانفیگ + سایفون" text, or its "پل + سایفون" twin in Bridge + Psiphon sessions */
    private String cl(String chainFa, String bridgeFa) { return L.t(cBridge ? bridgeFa : chainFa); }

    /**
     * v1.8.4 Bridge + Psiphon: makes sure there is a bridge to start with (pinned or one that passed the Psiphon
     * test); otherwise waits for a running test, or fetches the lists (when empty) and runs the Psiphon test once.
     */
    private boolean bridgePsiReady(final int myGen) {
        if (Bridges.sessionBridge(this) != null) return true;
        if (Bridges.busy) {
            stateMsg = L.t("پل + سایفون: منتظر تست پل‌ها…");
            long end = System.currentTimeMillis() + 300_000;
            while (Bridges.busy && System.currentTimeMillis() < end && !stopping && myGen == gen) {
                try { Thread.sleep(500); } catch (InterruptedException e) { return false; }
            }
            if (Bridges.sessionBridge(this) != null) return true;
        }
        if (stopping || myGen != gen || Bridges.busy) return false;
        if (Bridges.userList(this).isEmpty() && Bridges.poolSize(this) == 0) {
            stateMsg = L.t("پل + سایفون: دریافت فهرست پروکسی‌ها…");
            Bridges.fetch(this);
        }
        if (stopping || myGen != gen) return false;
        stateMsg = L.t("پل + سایفون: تست پل‌ها با سایفون قبل از اتصال (تا چند دقیقه)…");
        Core.log(stateMsg);
        Bridges.busy = true;
        try { Bridges.test(this, Bridges.PSI_MAX); } finally { Bridges.busy = false; }
        return Bridges.sessionBridge(this) != null;
    }

    /** v1.8.3: "Config + Psiphon: " or, while reconnecting, "Config + Psiphon: reconnecting #n — " */
    private String chainPrefix() {
        int n = cAttempts;
        return n > 0 ? cl("کانفیگ + سایفون: اتصال دوباره #", "پل + سایفون: اتصال دوباره #") + n + L.t(" — ") : cl("کانفیگ + سایفون: ", "پل + سایفون: ");
    }

    /**
     * v1.8.3: starts the chain, retrying until it is up or the user disconnects. Before every retry: failover after
     * 2 failed recoveries on the same config, then the backoff delay (2, 5, 10, 20, 30 s cap) with "#n" shown.
     */
    private Servers.Plan chainStartLoop(final int myGen) throws Exception {
        while (true) {
            if (stopping || myGen != gen) throw new InterruptedException("cancelled");
            if (cAttempts > 0 && cNoDelay) {
                // v1.8.5 Bridge + Psiphon: switching to another bridge (stall switch / refused bridge): no backoff
                cNoDelay = false;
                Core.log("WLOG chain reconnect #" + cAttempts + " now (bridge switch, no backoff)");
                stateMsg = L.t("پل + سایفون: تعویض پل…");
            } else if (cAttempts > 0) {
                if (cFailStreak >= 2) chainFailover();
                long d = C_BACKOFF[Math.min(cAttempts - 1, C_BACKOFF.length - 1)];
                Core.log("WLOG chain reconnect #" + cAttempts + " in " + d / 1000 + " s");
                long until = System.currentTimeMillis() + d;
                while (System.currentTimeMillis() < until) {
                    if (stopping || myGen != gen) throw new InterruptedException("cancelled");
                    long left = (until - System.currentTimeMillis() + 999) / 1000;
                    stateMsg = cl("کانفیگ + سایفون: اتصال دوباره #", "پل + سایفون: اتصال دوباره #") + cAttempts + L.t(" — ") + left + L.t(" ثانیه دیگر…");
                    Thread.sleep(250);
                }
                stateMsg = cl("کانفیگ + سایفون: اتصال دوباره #", "پل + سایفون: اتصال دوباره #") + cAttempts + "…";
            }
            try {
                return chainPlan(myGen);
            } catch (InterruptedException e) {
                throw e;
            } catch (Chain.BridgeRefused e) {
                if (stopping || myGen != gen) throw new InterruptedException("cancelled");
                // v1.8.5: the bridge failed its proxy check at connect time (e.g. refused): skip it for this
                // session and go straight to the next healthy one instead of retrying it
                String bad = Bridges.addrOf(e.key);
                synchronized (bRefused) { bRefused.add(bad); }
                synchronized (cTried) { cTried.add(bad); }
                Core.log(L.t("خطا: ") + e.getMessage());
                String nk = nextBridge(bad);
                cAttempts++;
                if (state == ST_ON) state = ST_RECONNECTING;
                if (nk != null) {
                    Bridges.sessionKey = nk;
                    cNoDelay = true;
                    Core.log(L.t("پل رد شد؛ پل سالم بعدی: ") + e.key + " ← " + nk);
                    Core.log("WLOG bridge+psiphon: " + e.key + " failed its proxy check at connect time -> skipped (session), next healthy bridge " + nk);
                } else {
                    synchronized (bRefused) { bRefused.clear(); }
                    cFailStreak++;
                    Core.log("WLOG bridge+psiphon: " + e.key + " failed its proxy check and no other healthy bridge is left; reconnect #" + cAttempts + " with backoff");
                }
            } catch (Exception e) {
                if (stopping || myGen != gen) throw new InterruptedException("cancelled");
                cFailStreak++;
                cAttempts++;
                Core.log(L.t("خطا: ") + e.getMessage());
                Core.log("WLOG chain start failed; reconnect #" + cAttempts + ", failed recoveries on this config: " + cFailStreak);
                if (state == ST_ON) state = ST_RECONNECTING;
            }
        }
    }

    /** v1.8.3: next config that passed its last test (fastest first); then, if allowed, the best one without Psiphon */
    private void chainFailover() {
        if (cBridge) { bridgeFailover(); return; }
        cFailStreak = 0;
        JSONObject cur = Chain.effective(this);
        String curLink = cur == null ? "" : cur.optString("u");
        String curName = cur == null ? "-" : cur.optString("n");
        boolean psi = Chain.effectivePsi(this);
        java.util.List<JSONObject> cands = Chain.tested(this);
        synchronized (cTried) {
            cTried.add(curLink);
            for (JSONObject o : cands) {
                if (cTried.contains(o.optString("u"))) continue;
                Chain.overrideLink = o.optString("u");
                Core.log(L.t("تعویض خودکار کانفیگ: «") + curName + L.t("» ← «") + o.optString("n") + "» (" + o.optLong("ms") + "ms)");
                Core.log("WLOG chain failover: 2 failed recoveries on \"" + curName + "\" -> \"" + o.optString("n") + "\" (last test " + o.optLong("ms") + " ms)");
                return;
            }
            // every tested config was tried in this round
            cTried.clear();
        }
        JSONObject best = cands.isEmpty() ? cur : cands.get(0);
        if (best != null) Chain.overrideLink = best.optString("u");
        if (psi && Chain.noPsiFallback(this)) {
            Chain.overridePsi = Boolean.FALSE;
            Core.log(L.t("همهٔ کانفیگ‌ها با سایفون ناموفق بودند؛ «") + (best == null ? "-" : best.optString("n")) + L.t("» بدون سایفون امتحان می‌شود"));
            Core.log("WLOG chain failover: all configs failed with psiphon -> best config without psiphon (setting on)");
        } else {
            Core.log("WLOG chain failover: all " + cands.size() + " tested config(s) failed; starting a new round from the best one");
        }
    }

    /**
     * v1.8.4 Bridge + Psiphon: after 2 failed recoveries in a row through the current bridge, the next bridge that
     * passed the last test (best first, not yet tried in this round). Only this session's choice changes
     * (Bridges.sessionKey); the user's pinned bridge and the saved results stay as they are.
     */
    private void bridgeFailover() {
        cFailStreak = 0;
        JSONObject cur = Bridges.sessionBridge(this);
        String curKey = cur == null ? "-" : cur.optString("k");
        java.util.List<JSONObject> cands = Bridges.passed(this);
        synchronized (cTried) {
            if (cur != null) cTried.add(Bridges.addrOf(curKey));
            for (JSONObject o : cands) {
                String k = o.optString("k");
                if (cTried.contains(Bridges.addrOf(k))) continue;
                Bridges.sessionKey = k;
                Core.log(L.t("تعویض خودکار پل: ") + curKey + " ← " + k + " (" + o.optLong("rms") + "ms)");
                Core.log("WLOG bridge+psiphon failover: 2 failed recoveries on " + curKey + " -> " + k + " (last test " + o.optLong("rms") + " ms)");
                return;
            }
            cTried.clear();
        }
        if (!cands.isEmpty()) Bridges.sessionKey = cands.get(0).optString("k");
        Core.log("WLOG bridge+psiphon failover: all " + cands.size() + " tested bridge(s) failed; starting a new round from the best one");
    }

    /**
     * v1.8.5 Bridge + Psiphon: the next bridge to switch to: the warm standby (its proxy handshake passed in the last
     * 3 min), else the next bridge that passed the last Psiphon test (best first, not tried in this round), else any
     * passed one. Never the current one or one that refused this session. null = none.
     */
    private String nextBridge(String curAddr) {
        java.util.Set<String> refused;
        synchronized (bRefused) { refused = new java.util.HashSet<>(bRefused); }
        String w = bWarmKey;
        if (!w.isEmpty() && System.currentTimeMillis() - bWarmAt < 180_000 && !Bridges.addrOf(w).equals(curAddr)
                && !refused.contains(Bridges.addrOf(w))) return w;
        java.util.List<JSONObject> cands = Bridges.passed(this);
        synchronized (cTried) {
            for (JSONObject o : cands) {
                String a = Bridges.addrOf(o.optString("k"));
                if (!a.equals(curAddr) && !refused.contains(a) && !cTried.contains(a)) return o.optString("k");
            }
        }
        for (JSONObject o : cands) {
            String a = Bridges.addrOf(o.optString("k"));
            if (!a.equals(curAddr) && !refused.contains(a)) return o.optString("k");
        }
        return null;
    }

    /**
     * v1.8.5 Bridge + Psiphon: NODATA after 40 s (svpn: no data and 3 failed DNS probes). When the chain's own
     * keep-alive fails too (or Psiphon has no tunnel), switch at once to the next healthy bridge, warm standby
     * first, instead of waiting for 2 failed recoveries. Session only; the pin and the saved results stay.
     */
    private boolean bridgeStallSwitch(Chain.Run r, String why) {
        if (r == null || r.dead) return false;
        boolean kaDead = r.kaFails >= 1 || r.tunnels == 0;
        if (!kaDead) {
            Core.log("WLOG bridge+psiphon " + why + ": keep-alive still passing -> psiphon recovery first");
            return false;
        }
        String cur = Bridges.addrOf(r.bridgeKey);
        String nk = nextBridge(cur);
        if (nk == null) {
            Core.log("WLOG bridge+psiphon " + why + ": no other healthy bridge -> psiphon recovery");
            return false;
        }
        synchronized (cTried) { cTried.add(cur); }
        Bridges.sessionKey = nk;
        boolean warm = nk.equals(bWarmKey);
        if (warm) bWarmKey = "";
        bWarmDue = System.currentTimeMillis() + 10_000; // find a new standby soon
        cNoDelay = true;
        Core.log(L.t("تعویض فوری پل (بدون داده ۴۰ ثانیه): ") + r.bridgeKey + " ← " + nk);
        Core.log("WLOG bridge+psiphon stall switch: " + why + ", keep-alive fails=" + r.kaFails + ", psiphon tunnels=" + r.tunnels
                + " -> " + nk + (warm ? " (warm standby, handshake " + bWarmMs + " ms)" : " (next tested bridge)"));
        stateMsg = L.t("پل + سایفون: تعویض پل…");
        state = ST_RECONNECTING;
        switchReq = true;
        switchWhy = why + " -> bridge switch";
        killProc();
        return true;
    }

    /**
     * v1.8.5 Bridge + Psiphon warm standby: every 60 s (10 s after a switch) a proxy handshake + TLS check of up to 3
     * other bridges that passed the last Psiphon test; the fastest that answers is the standby for a stall switch.
     */
    private void startBridgeStandby(final int myGen) {
        bWarmDue = System.currentTimeMillis() + 15_000;
        new Thread(() -> {
            while (!stopping && myGen == gen) {
                try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
                if (System.currentTimeMillis() < bWarmDue) continue;
                bWarmDue = System.currentTimeMillis() + 60_000;
                if (stopping || myGen != gen || (state != ST_ON && state != ST_RECONNECTING)) continue;
                Chain.Run r = cRun;
                String cur = Bridges.addrOf(r != null ? r.bridgeKey : Bridges.sessionKey);
                java.util.Set<String> refused;
                synchronized (bRefused) { refused = new java.util.HashSet<>(bRefused); }
                java.util.List<String> keys = new java.util.ArrayList<>(), urls = new java.util.ArrayList<>();
                for (JSONObject o : Bridges.passed(this)) {
                    String k = o.optString("k"), a = Bridges.addrOf(k);
                    if (a.equals(cur) || refused.contains(a)) continue;
                    keys.add(k);
                    urls.add(o.optString("u", k));
                    if (keys.size() >= 3) break;
                }
                if (keys.isEmpty()) {
                    if (!bWarmKey.isEmpty()) Core.log("WLOG bridge+psiphon standby: no other tested bridge");
                    bWarmKey = "";
                    continue;
                }
                long[] ms = Chain.checkProxies(this, urls, 6);
                if (stopping || myGen != gen) return;
                int best = -1;
                for (int i = 0; i < ms.length; i++) if (ms[i] > 0 && (best < 0 || ms[i] < ms[best])) best = i;
                if (best < 0) {
                    Core.log("WLOG bridge+psiphon standby: none of " + keys.size() + " bridge(s) answered the proxy check");
                    bWarmKey = "";
                    continue;
                }
                String k = keys.get(best);
                if (!k.equals(bWarmKey)) Core.log("WLOG bridge+psiphon standby: " + k + " ready (handshake " + ms[best] + " ms, " + keys.size() + " checked)");
                bWarmKey = k;
                bWarmMs = ms[best];
                bWarmAt = System.currentTimeMillis();
            }
        }, "o76-bstandby").start();
    }

    /**
     * v1.8.3: svpn reported NODATA in chain mode. First restart only the Psiphon layer inside libchain (Xray, its
     * SOCKS port and the svpn/TUN stay up); if that fails or brings no data, the full chain restarts.
     */
    private void chainNoData(final Process svpn, final int myGen, final String why) {
        if (cRecovering) { Core.log("WLOG chain " + why + " while recovering; waiting"); return; }
        final Chain.Run r = cRun;
        if (cBridge && bridgeStallSwitch(r, why)) return; // v1.8.5: 40 s stall -> next healthy bridge at once
        if (r == null || r.dead || cPartialNoUp >= 1) {
            String w = r == null || r.dead ? "core gone" : "partial recovery brought no data";
            Core.log("WLOG chain " + why + ": " + w + " -> full chain restart");
            if (r != null && !r.dead && cPartialNoUp >= 1) cFailStreak++;
            switchReq = true;
            switchWhy = why + " (" + w + ")";
            killProc();
            return;
        }
        cRecovering = true;
        final int n = ++cRecNo;
        state = ST_RECONNECTING;
        stateMsg = (cBridge ? L.t("پل + سایفون: بازیابی لایهٔ سایفون #") : r.psi ? L.t("کانفیگ + سایفون: بازیابی لایهٔ سایفون #") : L.t("کانفیگ + سایفون: بازیابی کانفیگ #")) + n + "…";
        Core.log("WLOG chain recover #" + n + ": " + why + " -> partial restart (" + (r.psi ? "psiphon only; xray, socks port and tun kept" : "xray check/restart; tun kept") + ")");
        new Thread(() -> {
            boolean ok = false;
            String msg;
            try {
                r.recoverResult = 0;
                if (!r.send("RECOVER")) msg = "control write failed";
                else {
                    long t0 = System.currentTimeMillis();
                    while (r.recoverResult == 0 && !r.dead && !stopping && myGen == gen && proc == svpn
                            && System.currentTimeMillis() - t0 < 150_000) {
                        try { Thread.sleep(300); } catch (InterruptedException e) { return; }
                    }
                    ok = r.recoverResult == 1;
                    msg = r.recoverResult == 0 ? (r.dead ? "core exited" : "no answer in 150 s") : r.recoverMsg;
                }
            } finally {
                cRecovering = false;
            }
            if (stopping || myGen != gen || proc != svpn) return;
            if (ok) {
                cPartialNoUp++;
                noData = false;
                stateMsg = cl("کانفیگ + سایفون: سایفون دوباره وصل شد، بررسی داده…", "پل + سایفون: سایفون دوباره وصل شد، بررسی داده…");
                Core.log("WLOG chain recover #" + n + " ok (" + msg + "); waiting for data through svpn");
            } else {
                cFailStreak++;
                Core.log("WLOG chain recover #" + n + " failed (" + msg + ") -> full chain restart; failed recoveries on this config: " + cFailStreak);
                if (!switchReq) {
                    switchReq = true;
                    switchWhy = "NODATA, partial recovery failed: " + msg;
                    killProc();
                }
            }
        }, "o76-chain-recover").start();
    }

    private void stopChain() {
        Chain.Run r = cRun;
        cRun = null;
        Chain.stop(r);
    }

    /** v1.8.2: the Config + Psiphon core exiting (config or Psiphon dropped) restarts the pair */
    private void watchChain(final Chain.Run r, final Process svpn, final int myGen) {
        new Thread(() -> {
            while (!stopping && myGen == gen && cRun == r && proc == svpn) {
                try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
                if (r.dead && !switchReq && proc == svpn) {
                    switchReq = true;
                    switchWhy = "CHAIN-EXIT" + (r.err.isEmpty() ? "" : " " + r.err);
                    killProc();
                    return;
                }
            }
        }, "o76-chain-watch").start();
    }

    /** v1.8: the warp-plus core exiting restarts the pair */
    private void watchWp(final WarpPlus.Run r, final Process svpn, final int myGen) {
        new Thread(() -> {
            while (!stopping && myGen == gen && wRun == r && proc == svpn) {
                try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
                if (r.dead && !switchReq && proc == svpn) {
                    switchReq = true;
                    switchWhy = "WPLUS-EXIT" + (r.err.isEmpty() ? "" : " " + r.err);
                    killProc();
                    return;
                }
            }
        }, "o76-wplus-watch").start();
    }

    private void stopFox() {
        Fox.Run r = fRun;
        fRun = null;
        Fox.stop(r);
    }

    /** v1.7: the Firefox core exiting (account rejected, quota used up, tunnel failed) restarts the pair */
    private void watchFox(final Fox.Run r, final Process svpn, final int myGen) {
        new Thread(() -> {
            while (!stopping && myGen == gen && fRun == r && proc == svpn) {
                try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
                if (!r.quota.isEmpty()) foxQuota = Fox.quotaFa(r.quota);
                if (r.dead && !switchReq && proc == svpn && fRun == r) {
                    String why = "FIREFOX-EXIT" + (r.err.isEmpty() ? "" : " " + r.err);
                    if (!Fox.signedIn(this) || Fox.quotaEmpty(r.quota)) {
                        // v1.8.5: reconnecting cannot help: signed out / quota used up
                        fFatal = true;
                        stateMsg = L.t("خطا: Firefox: ") + (r.err.isEmpty() ? L.t("حساب خارج شد یا سهمیه تمام شد") : r.err);
                        switchReq = true;
                        switchWhy = why;
                        killProc();
                    } else {
                        foxRestart(svpn, myGen, why); // v1.8.5: libfpn only, svpn + TUN kept
                    }
                    return;
                }
            }
        }, "o76-fox-watch").start();
    }

    private void stopAether() {
        Aether.Run r = aRun;
        aRun = null;
        Aether.stop(r);
    }

    /**
     * v1.6: while svpn runs, watches the Aether process: exit, or no validated tunnel 120 s after a drop (30 s idle)
     * (Aether itself never gives up), restarts the pair.
     */
    private void watchAether(final Aether.Run r, final Process svpn, final int myGen) {
        new Thread(() -> {
            while (!stopping && myGen == gen && aRun == r && proc == svpn) {
                try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
                aetherExit = r.exit;
                if (!r.endpoint.isEmpty()) endpoint = r.endpoint;
                String why = null;
                if (r.dead) why = "AETHER-EXIT";
                else if (r.exitLoc && r.w.exitFallback()) {
                    // v1.6.1: WARP's exit for Iranian users geolocates as IR: --exit-loc !IR rejects every working tunnel
                    r.exitLoc = false; // handle once
                    Aether.disableExitLocAfterIR(this);
                    why = "AETHER-EXIT-IR";
                } else if (r.downSince > 0) {
                    // v1.6.1: a validated tunnel that dropped gets 120 s to re-validate, unless Aether shows no progress
                    // at all for 30 s while not mid-scan/handshake
                    long now = System.currentTimeMillis();
                    int ph = r.w.phase();
                    boolean busy = ph == AetherWatch.PH_SCAN_FOUND || ph == AetherWatch.PH_HANDSHAKE;
                    if (now - r.downSince > Aether.DOWN_MS) why = "AETHER-DOWN";
                    else if (!busy && now - r.w.lastProgress() > Aether.DOWN_IDLE_MS) why = "AETHER-DOWN-IDLE";
                }
                if (r.downSince > 0 && state == ST_ON) { state = ST_RECONNECTING; stateMsg = L.t("Aether: تونل قطع شد، اتصال دوباره…"); }
                if (r.downSince == 0 && r.validated && state == ST_RECONNECTING && !noData) { state = ST_ON; stateMsg = L.t("متصل"); }
                if (why != null && !switchReq && proc == svpn) {
                    switchReq = true;
                    switchWhy = why;
                    killProc();
                    return;
                }
            }
        }, "o76-aether-watch").start();
    }

    private void markCurrentFailed(Servers.Plan plan) {
        JSONObject cur = "h3".equals(proto) ? plan.h3 : plan.h2;
        if (cur == null) cur = plan.h2;
        Servers.markFailed(this, cur);
    }

    /** Runs one core process with the given plan until it exits; returns its exit code. */
    private int runCore(Servers.Plan plan, int myGen) throws Exception {
        final File sock = new File(getFilesDir(), "tun.sock");
        final boolean pinned = plan.pinned;
        bridgeInUse = plan.bridgeKey == null ? "" : plan.bridgeKey;
        final boolean aether = plan.aetherPort > 0;
        Core.log(L.t("اتصال [") + Core.modeLabel(modeInUse) + "]: " + plan.describe() + (pinned ? L.t(" (سنجاق‌شده)") : L.t(" (خودکار)"))
                + (plan.standby.isEmpty() ? "" : " + " + plan.standby.size() + L.t(" پل آماده")));
        java.util.List<String> args = new java.util.ArrayList<>();
        if (aether) {
            // v1.6: TUN -> o76core svpn -> Aether's local SOCKS5
            args.add("svpn");
            args.add("-socks"); args.add("127.0.0.1:" + plan.aetherPort);
            args.add("-mtu"); args.add(String.valueOf(Core.mtu(this)));
            if (plan.chain) {
                // v1.8.3: tolerate short stalls (50 s window + 3 failed probes in a row), 5 s probes that overlap,
                // any relayed byte = liveness, IPv6/private destinations refused at once.
                // v1.8.5 Bridge + Psiphon: 40 s window; with a failing keep-alive the app switches to the next bridge
                args.add("-chain");
                args.add("-nodata"); args.add(cBridge ? "40s" : "50s");
            } else if (plan.fox) {
                // v1.8.5: Firefox gets the chain-mode tolerance (50 s + 3 failed probes, overlapping 8 s probes, any
                // relayed byte = liveness, no FAILS) but keeps IPv6
                args.add("-tolerant");
                args.add("-nodata"); args.add("50s");
            } else {
                args.add("-nodata"); args.add("30s");
            }
            if (plan.fox) {
                args.add("-dnsudp"); // v1.7: the Firefox core answers DNS (UDP ASSOCIATE) with encrypted DNS in its tunnel
                Fox.Run fr = fRun;
                proto = fr == null || fr.proto.isEmpty() ? "h2" : fr.proto;
                endpoint = fr == null || fr.loc.isEmpty() ? "Firefox" : fr.loc;
                sniUsed = "-";
            } else if (plan.chain) {
                Chain.Run cr = cRun;
                proto = cr != null && cr.psi ? "psiphon" : "xray";
                endpoint = cr == null ? cl("کانفیگ + سایفون", "پل + سایفون") : cr.name;
                sniUsed = "-";
            } else if (plan.wp) {
                WarpPlus.Run wr = wRun;
                proto = "wg";
                endpoint = wr == null ? L.t("وارپ+") : wr.label + (wr.endpoint.isEmpty() ? "" : " " + wr.endpoint);
                sniUsed = "-";
            } else {
                Aether.Run ar = aRun;
                proto = Aether.proto(this);
                endpoint = ar == null || ar.endpoint.isEmpty() ? "Aether" : ar.endpoint;
                sniUsed = Aether.P_WG.equals(proto) ? "-" : Aether.sni(this);
            }
        } else {
            args.add("vpn"); args.add("-c"); args.add(Core.cfg(this).getAbsolutePath());
            args.addAll(plan.coreArgs());
            args.addAll(Core.dpiArgs(this));
            args.add("-nodata"); args.add("8s");
        }
        args.add("-sock"); args.add(sock.getAbsolutePath());
        final Process p = Core.start(this, args.toArray(new String[0]));
        proc = p;
        socksPort = aether ? plan.aetherPort : 0;
        if (aether && plan.fox && fRun != null) watchFox(fRun, p, myGen);
        else if (aether && plan.wp && wRun != null) watchWp(wRun, p, myGen);
        else if (aether && plan.chain && cRun != null) watchChain(cRun, p, myGen);
        else if (aether && aRun != null) watchAether(aRun, p, myGen);
        final long[] last = {0, 0, System.currentTimeMillis()};
        final long[] base = {rxTotal, txTotal};
        final int[] stalls = {0};
        return Core.pump(p, line -> {
            if (line.equals("READY")) {
                try {
                    sendFd(sock.getAbsolutePath(), tun.getFileDescriptor());
                } catch (Exception e) {
                    Core.log("send fd failed: " + e);
                }
            } else if (line.startsWith("TRY ")) {
                String[] s = line.split(" ");
                stateMsg = L.t("تلاش با ") + Core.protoLabel(s[1]) + " …";
            } else if (line.equals("H3FAIL")) {
                Core.prefs(this).edit().putLong("h3FailAt", System.currentTimeMillis()).putString("lastProto", "h2").apply();
                Core.log(L.t("HTTP/3 در ۳ ثانیه وصل نشد ← HTTP/2"));
            } else if (line.startsWith("PROTO ")) {
                String[] s = line.split(" ");
                if (s.length >= 4) {
                    proto = s[1]; endpoint = s[2]; sniUsed = s[3];
                    Core.prefs(this).edit().putString("lastProto", proto)
                            .putLong("h3FailAt", "h3".equals(proto) ? 0 : Core.prefs(this).getLong("h3FailAt", 0)).apply();
                    Servers.markOk(this, s[1], s[2], s[3]);
                }
            } else if (line.equals("STATE up")) {
                boolean first = state != ST_ON;
                state = ST_ON;
                stateMsg = L.t("متصل");
                stalls[0] = 0;
                if (aether && plan.fox) {
                    fUpAt = System.currentTimeMillis();
                    if (fAttempts > 0) Core.log("WLOG firefox data flows again (reconnects reset)");
                    fAttempts = 0;
                }
                else if (aether && plan.wp) wUpAt = System.currentTimeMillis();
                else if (aether && plan.chain) {
                    cUpAt = System.currentTimeMillis();
                    if (cAttempts > 0 || cFailStreak > 0 || cPartialNoUp > 0) Core.log("WLOG chain data flows again (reconnects reset)");
                    cGotData = true;
                    cAttempts = 0;
                    cFailStreak = 0;
                    cPartialNoUp = 0;
                    synchronized (cTried) { cTried.clear(); }
                }
                else if (aether) aUpAt = System.currentTimeMillis();
                if (first) {
                    Core.log(L.t("متصل شد: ") + Core.protoLabel(proto) + " " + endpoint + " [" + sniUsed + "]" + (bridgeInUse.isEmpty() ? "" : " via " + bridgeInUse));
                    if (aether && !aetherExit.isEmpty()) Core.log((plan.fox ? "Firefox" : plan.wp ? L.t("وارپ+") : plan.chain ? cl("کانفیگ + سایفون", "پل + سایفون") : "Aether") + L.t(" خروجی: ") + aetherExit);
                    if (!bridgeInUse.isEmpty()) Bridges.markOk(this, bridgeInUse);
                }
            } else if (line.startsWith("BSWITCH ")) {
                // core switched to a warm standby bridge on its own (no restart)
                String[] s = line.split(" ");
                if (s.length >= 3) {
                    Bridges.markFailedKey(this, s[1]);
                    bridgeInUse = s[2];
                    switches++;
                    realRtt = 0;
                    noData = false;
                    Core.log(L.t("تعویض فوری پل (") + (s.length >= 4 ? s[3] : "") + "): " + s[1] + " ← " + s[2]);
                }
                Core.log(line);
            } else if (line.startsWith("WLOG ")) {
                Core.log(line); // svpn stage lines
            } else if (line.startsWith("BINTL ")) {
                Core.log(line);
            } else if (line.startsWith("BWARM ") || line.startsWith("BSTANDBY ")) {
                if (line.contains(" fail ")) Core.log(L.t("پل آماده از دسترس خارج شد: ") + line.substring(6));
                else if (line.startsWith("BSTANDBY ")) Core.log(line);
            } else if (line.startsWith("TTLDROPS ")) {
                try { ttlDrops = Long.parseLong(line.substring(9).trim()); } catch (Exception ignored) { }
            } else if (line.startsWith("WERR ")) {
                Core.log("svpn: " + line.substring(5));
            } else if (line.equals("STATE down")) {
                if (state == ST_ON || state == ST_CONNECTING) {
                    state = ST_RECONNECTING;
                    stateMsg = L.t("اتصال قطع شد، تلاش دوباره…");
                }
            } else if (line.startsWith("RTT ")) {
                try { realRtt = Long.parseLong(line.substring(4).trim()); } catch (Exception ignored) { }
                if (aether && plan.chain) cPartialNoUp = 0;
                if (noData) {
                    noData = false;
                    if (state == ST_ON) stateMsg = L.t("متصل");
                    Core.log(L.t("داده دوباره رد می‌شود (تاخیر واقعی ") + realRtt + "ms)");
                }
            } else if (line.startsWith("NODATA ")) {
                // tunnel says "connected" but nothing comes back (DPI stalls the stream after the handshake)
                noData = true;
                Core.log(L.t("متصل ولی داده‌ای برنمی‌گردد (") + line + ")");
                if (myGen == gen && !stopping) {
                    if (aether && plan.chain) {
                        if (!switchReq) chainNoData(p, myGen, line);
                    } else if (aether && plan.fox) {
                        if (!switchReq) {
                            stateMsg = L.t("داده رد نمی‌شود؛ اتصال دوباره Firefox…");
                            foxRestart(p, myGen, line);
                        }
                    } else if (pinned) {
                        stateMsg = L.t("متصل ولی داده رد نمی‌شود — ") + (bridgeInUse.isEmpty() ? L.t("سرور") : L.t("پل")) + L.t(" سنجاق‌شده است (سنجاق را بردارید تا خودکار عوض شود)");
                    } else if (!switchReq) {
                        stateMsg = aether ? (plan.fox ? L.t("داده رد نمی‌شود؛ اتصال دوباره Firefox…") : plan.wp ? L.t("داده رد نمی‌شود؛ اتصال دوباره وارپ+…")
                                : plan.chain ? L.t("داده رد نمی‌شود؛ اتصال دوباره کانفیگ + سایفون…") : L.t("داده رد نمی‌شود؛ راه‌اندازی دوباره Aether…"))
                                : L.t("داده رد نمی‌شود؛ تعویض سرور/SNI…");
                        switchReq = true;
                        switchWhy = "NODATA";
                        killProc();
                    }
                }
            } else if (line.startsWith("FAILS ") || line.startsWith("STALL ")) {
                int n = 0;
                try { n = Integer.parseInt(line.substring(6).trim()); } catch (Exception ignored) { }
                if (line.startsWith("STALL ")) n = ++stalls[0] + 1; // first stall counts as a 2nd failure
                // SOCKS-based modes fail over only after 3 consecutive failures (the core retries first)
                final int need = aether ? 3 : 2;
                if (aether && line.startsWith("FAILS ")) Core.log(line);
                if (aether && plan.chain) {
                    // v1.8.3: chain mode recovers on NODATA only (svpn -chain does not send FAILS)
                } else if (n >= need && myGen == gen && !stopping) {
                    if (pinned) {
                        if (n == need) Core.log(L.t("سرور سنجاق‌شده پاسخ نمی‌دهد؛ تعویض خودکار غیرفعال است (سنجاق را بردارید)"));
                        if (n == need && bridgeInUse.isEmpty() && !aether) Servers.startScan(this);
                    } else if (!switchReq) {
                        switchReq = true;
                        switchWhy = line;
                        killProc();
                    }
                }
            } else if (line.startsWith("OPTS ")) {
                Core.log(line);
            } else if (line.startsWith("STAT ")) {
                String[] s = line.split(" ");
                try {
                    long rx = base[0] + Long.parseLong(s[1]), tx = base[1] + Long.parseLong(s[2]);
                    long now = System.currentTimeMillis();
                    double dt = Math.max(0.2, (now - last[2]) / 1000.0);
                    if (last[0] > 0 || last[1] > 0) {
                        downBps = (rx - last[0]) / dt;
                        upBps = (tx - last[1]) / dt;
                    }
                    last[0] = rx; last[1] = tx; last[2] = now;
                    rxTotal = rx; txTotal = tx;
                } catch (Exception ignored) { }
            } else if (line.startsWith("ERR")) {
                stateMsg = L.t("خطا: ") + line.substring(3).trim();
                Core.log(line);
            } else {
                Core.log(line);
            }
        });
    }

    /**
     * v1.4: while connected through a bridge, re-test the known-good bridges (+ a few new ones) every ~20 min and
     * hand the fresh warm standby set to the running core over stdin ("BRIDGES url,url").
     */
    private void startBridgeRetest(final int myGen) {
        new Thread(() -> {
            while (!stopping && myGen == gen) {
                try { Thread.sleep(20L * 60 * 1000); } catch (InterruptedException e) { return; }
                if (stopping || myGen != gen || state != ST_ON) continue;
                Core.log(L.t("تست دوره‌ای پل‌ها (هر ۲۰ دقیقه) …"));
                int n = Bridges.retest(this);
                if (n < 0 || stopping || myGen != gen) continue;
                pushBridges();
            }
        }, "o76-bretest").start();
    }

    /**
     * v1.5: called after a bridge refetch / test (Bridges.startFetch, startTest) so a running core gets the fresh
     * standby set at once. No-op when no tunnel runs through a bridge.
     */
    public static void bridgesUpdated(android.content.Context c) {
        O76VpnService s = instance;
        if (s == null || s.stopping) return;
        if (state != ST_ON && state != ST_RECONNECTING) return;
        s.pushBridges();
    }

    /** sends "BRIDGES url,url" (standbys, current bridge excluded) to the running core's stdin */
    private synchronized void pushBridges() {
        Process p = proc;
        String cur = bridgeInUse;
        if (p == null || cur.isEmpty()) return; // direct tunnel: the core has no bridge set
        if (!Core.MODE_BRIDGE.equals(modeInUse) || cBridge) return; // only the MASQUE-over-bridge core has a bridge set
        java.util.List<String> ws = Bridges.warmSet(this, cur, 3);
        if (ws.isEmpty()) return;
        StringBuilder sb = new StringBuilder("BRIDGES ");
        for (int i = 0; i < ws.size(); i++) { if (i > 0) sb.append(','); sb.append(ws.get(i)); }
        sb.append('\n');
        try {
            OutputStream os = p.getOutputStream();
            os.write(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            os.flush();
            Core.log(L.t("فهرست پل‌های آماده به هسته داده شد: ") + ws.size());
        } catch (Exception e) {
            Core.log("standby update: " + e.getMessage());
        }
    }

    private static void sendFd(String path, FileDescriptor fd) throws Exception {
        LocalSocket ls = new LocalSocket();
        try {
            ls.connect(new LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM));
            ls.setFileDescriptorsForSend(new FileDescriptor[]{fd});
            OutputStream os = ls.getOutputStream();
            os.write(42);
            os.flush();
            Thread.sleep(200);
        } finally {
            ls.close();
        }
    }

    private void killProc() {
        Process p = proc;
        proc = null;
        if (p != null) {
            try { p.getOutputStream().close(); } catch (Exception ignored) { }
            p.destroy();
        }
    }

    private void closeTun() {
        ParcelFileDescriptor t = tun;
        tun = null;
        if (t != null) {
            try { t.close(); } catch (Exception ignored) { }
        }
    }

    private void stopVpn(String msg) {
        stopping = true;
        killProc();
        stopAether();
        stopFox();
        stopWp();
        stopChain();
        chainStage = "";
        bridgePsi = false;
        socksPort = 0;
        aetherExit = "";
        foxQuota = "";
        closeTun();
        downBps = upBps = 0;
        bridgeInUse = "";
        modeInUse = "";
        if (msg != null) {
            state = ST_OFF;
            stateMsg = msg;
        }
        try { stopForeground(true); } catch (Exception ignored) { }
    }

    @Override
    public void onRevoke() {
        stopVpn(L.t("VPN توسط سیستم قطع شد"));
        stopSelf();
    }

    @Override
    public void onDestroy() {
        if (instance == this) instance = null;
        stopVpn(state == ST_ERROR ? null : L.t("قطع شد"));
        super.onDestroy();
    }
}
