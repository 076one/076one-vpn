package com.o76one.app;

/**
 * v1.6.1: the Aether startup watchdog as a pure state machine (no Android classes, unit-tested on the JVM by
 * test/aetherwatch/AetherWatchTest.java with real-device log lines).
 *
 * Field log (Iran, TCI, v1.6): Aether selected a gateway 39 s after start, TLS + connect-ip 200 passed, and our flat
 * 60 s timer killed it one second into data-plane validation. Rules now:
 * <ul>
 *   <li>Progress lines (candidate ok, selected gateway, tls established, connect-ip request/status, validating
 *       data-plane, tunnel validated, socks listening) reset the idle timer.</li>
 *   <li>Idle kill ({@link #IDLE_MS} since the last progress) only while nothing is happening: scanning with no answering
 *       gateway yet, or after a tunnel attempt ended. Never while a scan has candidates and has not finished, and never
 *       mid-handshake/validation.</li>
 *   <li>Hard cap {@link #HARD_MS} from start without any "tunnel validated".</li>
 *   <li>A validation followed by a non-fatal reconnect (tunnel ended / exit rejected) extends the deadline to
 *       {@link #REVALIDATE_MS} from that moment.</li>
 *   <li>Up = "tunnel validated" + "socks5 server listening"; the exit line may come later and is not waited for.</li>
 *   <li>"exit location IR rejected" twice -> {@link #exitFallback()}: the caller restarts Aether without --exit-loc.</li>
 * </ul>
 * All times are caller-supplied millis, so tests can replay a log with its own timestamps.
 */
public final class AetherWatch {
    public static final long IDLE_MS = 60_000;
    public static final long HARD_MS = 240_000;
    public static final long REVALIDATE_MS = 120_000;
    public static final int IR_REJECTS_FOR_FALLBACK = 2;

    public static final int PH_SCAN = 0, PH_SCAN_FOUND = 1, PH_HANDSHAKE = 2, PH_VALIDATED = 3, PH_ENDED = 4;
    private static final String[] PH_NAMES = {"scan", "scan-found", "handshake", "validated", "ended"};

    public final long startedAt;
    private long lastProgress, deadline;
    private int phase = PH_SCAN;
    private boolean validated, socksUp, everValidated;
    private int found, irRejects;
    private String exit = "";

    public AetherWatch(long now) {
        startedAt = now;
        lastProgress = now;
        deadline = now + HARD_MS;
    }

    /** Feeds one log message (the part after "[… LEVEL target] "). Returns true when it was a progress line. */
    public synchronized boolean onMsg(String m, long now) {
        if (m == null || m.isEmpty()) return false;
        boolean progress = false;
        if (m.contains("tunnel validated")) {
            validated = true;
            everValidated = true;
            phase = PH_VALIDATED;
            progress = true;
        } else if (m.contains("socks5 server listening")) {
            socksUp = true;
            progress = true;
        } else if (m.contains("tunnel ended") || m.contains("tunnel closed") || m.contains("no longer responds")
                || m.contains("startup timed out")) {
            // checked before the exit-location lines: "MASQUE tunnel ended: exit location changed to IR; reconnecting"
            // repeats the reason and must not be counted twice
            lost(now);
        } else if (m.contains("exit location") && m.contains("rejected")) {
            // "[-] exit location IR rejected (not IR)"
            if (isIR(m.substring(m.indexOf("exit location") + 13))) irRejects++;
            lost(now);
        } else if (m.contains("exit location changed to")) {
            // "[-] exit location changed to IR; reconnecting" (periodic re-check while up)
            if (isIR(m.substring(m.indexOf("changed to") + 10))) irRejects++;
            lost(now);
        } else if (m.contains(" exit: ")) {
            exit = m.substring(m.indexOf(" exit: ") + 7).trim();
        } else if (m.contains("candidate ok")) {
            found++;
            if (phase == PH_SCAN || phase == PH_ENDED) phase = PH_SCAN_FOUND;
            progress = true;
        } else if (m.contains("hunting for a working") || m.contains("scanning fresh")) {
            if (phase != PH_VALIDATED) phase = found > 0 ? PH_SCAN_FOUND : PH_SCAN;
            progress = true;
        } else if (m.contains("selected MASQUE gateway") || m.contains("using cloudflare edge")
                || m.contains("selected WireGuard") || m.contains("selected wireguard") || m.contains("still works")
                || m.contains("tls established") || m.contains("connect-ip request") || m.contains("connect-ip status")
                || m.contains("validating data-plane") || m.contains("handshake complete")) {
            if (phase != PH_VALIDATED) phase = PH_HANDSHAKE;
            progress = true;
        }
        if (progress) lastProgress = now;
        return progress;
    }

    private void lost(long now) {
        if (validated || everValidated) deadline = Math.max(deadline, now + REVALIDATE_MS);
        validated = false;
        phase = PH_ENDED;
        lastProgress = now; // the reconnect itself is activity; idle timer counts from here
    }

    private static boolean isIR(String rest) {
        String s = rest.trim();
        return s.startsWith("IR") && (s.length() == 2 || !Character.isLetter(s.charAt(2)));
    }

    /** null = keep waiting; otherwise the reason to kill (English tag, for the log/tests). */
    public synchronized String check(long now) {
        if (up()) return null;
        if (now > deadline) return everValidated ? "revalidate-timeout" : "hard-cap";
        boolean busy = phase == PH_SCAN_FOUND || phase == PH_HANDSHAKE || phase == PH_VALIDATED;
        if (!busy && now - lastProgress > IDLE_MS) return "idle";
        return null;
    }

    public synchronized boolean up() { return validated && socksUp; }
    public synchronized boolean validated() { return validated; }
    public synchronized boolean socksUp() { return socksUp; }
    public synchronized boolean exitFallback() { return irRejects >= IR_REJECTS_FOR_FALLBACK; }
    public synchronized int irRejects() { return irRejects; }
    public synchronized int found() { return found; }
    public synchronized int phase() { return phase; }
    public synchronized String phaseName() { return PH_NAMES[phase]; }
    public synchronized String exit() { return exit; }
    public synchronized long deadline() { return deadline; }
    public synchronized long lastProgress() { return lastProgress; }
}
