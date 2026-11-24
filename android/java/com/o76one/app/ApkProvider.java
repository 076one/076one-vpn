package com.o76one.app;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * v1.8.5: serves the downloaded, verified update APK (cache/update/*.apk) read-only to the system installer as a
 * content:// URI (Android 7+ forbids file:// URIs between apps). Not exported; access only through the one-off
 * read grant on the installer intent. A minimal stand-in for androidx FileProvider (the app has no androidx).
 */
public final class ApkProvider extends ContentProvider {
    public static final String AUTH = "com.o76one.app.apk";

    static Uri uri(File f) { return Uri.parse("content://" + AUTH + "/update/" + Uri.encode(f.getName())); }

    private File file(Uri u) throws FileNotFoundException {
        String n = u.getLastPathSegment();
        if (n == null || !n.endsWith(".apk") || n.contains("/") || n.contains("..")) throw new FileNotFoundException(String.valueOf(u));
        File f = new File(new File(getContext().getCacheDir(), "update"), n);
        if (!f.isFile()) throw new FileNotFoundException(n);
        return f;
    }

    @Override public boolean onCreate() { return true; }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (mode != null && !"r".equals(mode)) throw new FileNotFoundException("read-only");
        return ParcelFileDescriptor.open(file(uri), ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        File f;
        try { f = file(uri); } catch (FileNotFoundException e) { return null; }
        String[] cols = projection == null ? new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE} : projection;
        MatrixCursor c = new MatrixCursor(cols, 1);
        Object[] row = new Object[cols.length];
        for (int i = 0; i < cols.length; i++) {
            if (OpenableColumns.DISPLAY_NAME.equals(cols[i])) row[i] = f.getName();
            else if (OpenableColumns.SIZE.equals(cols[i])) row[i] = f.length();
        }
        c.addRow(row);
        return c;
    }

    @Override public String getType(Uri uri) { return Updater.MIME; }
    @Override public Uri insert(Uri uri, ContentValues values) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri uri, String s, String[] a) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri uri, ContentValues v, String s, String[] a) { throw new UnsupportedOperationException(); }
}
