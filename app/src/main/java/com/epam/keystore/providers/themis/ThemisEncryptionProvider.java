package com.epam.keystore.providers.themis;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;

import com.cossacklabs.themis.InvalidArgumentException;
import com.cossacklabs.themis.NullArgumentException;
import com.cossacklabs.themis.SecureCell;
import com.cossacklabs.themis.SecureCellData;
import com.cossacklabs.themis.SecureCellException;
import com.epam.keystore.core.SecureStorageCallback;
import com.epam.keystore.core.SecureStorageException;
import com.epam.keystore.core.SecurityProvider;

import java.nio.charset.StandardCharsets;

import static com.cossacklabs.themis.SecureCell.MODE_SEAL;
import static com.epam.keystore.core.SecureStorageCallback.ActionType.ERASE;
import static com.epam.keystore.core.SecureStorageCallback.ActionType.GET;
import static com.epam.keystore.core.SecureStorageCallback.ActionType.REMOVE;
import static com.epam.keystore.core.SecureStorageCallback.ActionType.SAVE;

/**
 * <h2>Themis encryption provider class</h2>
 * <b>Description:</b>
 * Encryption provider which logic is based on the Themis library
 * designed by CossackLabs
 * See <a href="https://github.com/cossacklabs/themis/wiki/Java-and-Android-Howto">GitHub CossackLabs</a>
 * Java Cipher implementation. Encapsulates two realizations
 * for M and PreM Android OS versions
 *
 * @author Denys Mokhrin
 */
public class ThemisEncryptionProvider implements SecurityProvider {

    private SharedPreferences preferences;
    private SecureStorageCallback callback;

    public ThemisEncryptionProvider(@NonNull Context context) {
        this.preferences = PreferenceManager.getDefaultSharedPreferences(context);
    }

    public ThemisEncryptionProvider(@NonNull Context context, SecureStorageCallback callback) {
        this.callback = callback;
        this.preferences = PreferenceManager.getDefaultSharedPreferences(context);
    }

    @Override
    public void save(@NonNull String key, @NonNull String value) {
        if (key == null || value == null || key.isEmpty() || value.isEmpty()) {
            if (callback != null) {
                callback.onError(SAVE, new SecureStorageException("Key or Value can't be NULL"));
            }
            return;
        }
        if (key != null && value != null) {
            key.trim();
            try {
                SecureCell sc = new SecureCell(key.getBytes(StandardCharsets.UTF_8), MODE_SEAL);
                SecureCellData protectedData = sc.protect(key.getBytes(StandardCharsets.UTF_8), value.getBytes(StandardCharsets.UTF_8));
                String encodedString = Base64.encodeToString(protectedData.getProtectedData(), Base64.NO_WRAP);

                this.preferences.edit().putString(key, encodedString).apply();

                if (callback != null) {
                    callback.onComplete(SAVE);
                }
            } catch (InvalidArgumentException | NullArgumentException | SecureCellException e) {
                e.printStackTrace();

                if (callback != null) {
                    callback.onError(SAVE, e);
                }
            }
        }
    }

    @Nullable
    @Override
    public String get(@NonNull String key) {
        if (key == null || key.isEmpty()) {
            if (callback != null) {
                callback.onError(GET, new SecureStorageException("Key or Value can't be NULL"));
            }
            return null;
        }
        try {
            String encodedString = preferences.getString(key, null);
            String decryptedData;
            if (encodedString != null) {
                byte[] decodedString = Base64.decode(encodedString, Base64.NO_WRAP);
                SecureCell sc = new SecureCell(key.getBytes(StandardCharsets.UTF_8), MODE_SEAL);

                SecureCellData protectedDataAgain = new SecureCellData(decodedString, null);

                byte[] unprotectedData = sc.unprotect(key.getBytes(StandardCharsets.UTF_8), protectedDataAgain);
                decryptedData = new String(unprotectedData, StandardCharsets.UTF_8);

                if (callback != null) {
                    callback.onComplete(GET);
                }

                return decryptedData;

            } else {
                if (callback != null) {
                    callback.onError(GET, new SecureStorageException("No Such Value"));
                }
                return null;
            }

        } catch (InvalidArgumentException | NullArgumentException | SecureCellException e) {
            e.printStackTrace();
            if (callback != null) {
                callback.onError(GET, e);
            }
        }
        return null;
    }

    @Override
    public void remove(@NonNull String key) {
        if (key == null || key.isEmpty()) {
            if (callback != null) {
                callback.onError(SAVE, new SecureStorageException("Key or Value can't be NULL or empty"));
            }
            return;
        }

        preferences.edit().remove(key).apply();
        if (callback != null) {
            callback.onComplete(REMOVE);
        }
    }

    @Override
    public void erase() {
        preferences.edit().clear().apply();

        if (callback != null) {
            callback.onComplete(ERASE);
        }
    }
}
