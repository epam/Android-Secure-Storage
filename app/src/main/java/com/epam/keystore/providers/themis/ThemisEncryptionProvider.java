package com.epam.keystore.providers.themis;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Base64;

import com.cossacklabs.themis.InvalidArgumentException;
import com.cossacklabs.themis.NullArgumentException;
import com.cossacklabs.themis.SecureCell;
import com.cossacklabs.themis.SecureCellData;
import com.cossacklabs.themis.SecureCellException;
import com.epam.keystore.core.SecureStorageException;
import com.epam.keystore.core.SecurityProvider;

import java.nio.charset.StandardCharsets;

import static com.cossacklabs.themis.SecureCell.MODE_SEAL;

public class ThemisEncryptionProvider implements SecurityProvider {

    private SharedPreferences preferences;

    public ThemisEncryptionProvider(Context context) {
        this.preferences = PreferenceManager.getDefaultSharedPreferences(context);
    }

    @Override
    public void save(String key, String value) {
        if (key != null && value != null) {
            key.trim();
            try {
                SecureCell sc = new SecureCell(key.getBytes(StandardCharsets.UTF_8), MODE_SEAL);
                SecureCellData protectedData = sc.protect(key.getBytes(StandardCharsets.UTF_8), value.getBytes(StandardCharsets.UTF_8));
                String encodedString = Base64.encodeToString(protectedData.getProtectedData(), Base64.NO_WRAP);

                this.preferences.edit().putString(key, encodedString).apply();
            } catch (InvalidArgumentException | NullArgumentException | SecureCellException e) {
                e.printStackTrace();
            }
        } else {
            new SecureStorageException("PasswordKey and Message can't be NULL");
        }
    }

    @Override
    public String get(String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key should not be null or empty");
        }

        try {
            String encodedString = preferences.getString(key, "No Such Value");

            byte[] decodedString = Base64.decode(encodedString, Base64.NO_WRAP);
            SecureCell sc = new SecureCell(key.getBytes(StandardCharsets.UTF_8), MODE_SEAL);

            SecureCellData protectedDataAgain = new SecureCellData(decodedString, null);

            byte[] unprotectedData = sc.unprotect(key.getBytes(StandardCharsets.UTF_8), protectedDataAgain);
            String decryptedData = new String(unprotectedData, StandardCharsets.UTF_8);

            return decryptedData;

        } catch (InvalidArgumentException | NullArgumentException | SecureCellException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void remove(String key) {
        preferences.edit().remove(key).apply();
    }

    @Override
    public void erase() {
        preferences.edit().clear().apply();
    }
}
