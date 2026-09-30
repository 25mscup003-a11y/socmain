package com.soc.agent;

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
 * Minimal file provider so the system package-installer can read a downloaded APK via a
 * content:// URI (required on API 24+). Implemented from scratch to avoid pulling in
 * androidx (this module builds with android.useAndroidX=false and no dependencies).
 * Only the OTA self-update APK is ever exposed, and only while an update is in flight.
 */
public class UpdateFileProvider extends ContentProvider {
    public static final String AUTHORITY = "com.soc.agent.updateprovider";
    private static volatile File currentFile;

    /** Register the file to be served and return the content URI pointing at it. */
    public static Uri uriFor(File file) {
        currentFile = file;
        return Uri.parse("content://" + AUTHORITY + "/" + file.getName());
    }

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        File file = currentFile;
        if (file == null || !file.exists()) throw new FileNotFoundException("No update file available");
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        File file = currentFile;
        if (file == null) return null;
        MatrixCursor cursor = new MatrixCursor(new String[]{ OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE }, 1);
        cursor.addRow(new Object[]{ file.getName(), file.length() });
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        return "application/vnd.android.package-archive";
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
