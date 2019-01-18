package com.epam.keystore.providers.themis;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import com.cossacklabs.themis.InvalidArgumentException;
import com.cossacklabs.themis.NullArgumentException;
import com.cossacklabs.themis.SecureCell;
import com.cossacklabs.themis.SecureCellException;
import com.epam.keystore.core.SecurityProvider;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.SecretKey;

import static com.cossacklabs.themis.SecureCell.MODE_SEAL;

public class ThemisEncryptionProvider implements SecurityProvider {

    private SharedPreferences preferences;
    private SecretKey secretKey;
    private KeyStore keyStore;

    private ThemisEncryptionProvider() {

    }

    public ThemisEncryptionProvider(Context context) {

    }

    @Override
    public void save(String key, String value) {
        if (key != null && value != null) {
            try {
                SecureCell sc = new SecureCell(key.getBytes(StandardCharsets.UTF_8), MODE_SEAL);
                sc.protect(key.getBytes(StandardCharsets.UTF_8), value.getBytes(StandardCharsets.UTF_8));

                Log.d("SMC", "Data has been encrypted");
            } catch (InvalidArgumentException | NullArgumentException | SecureCellException e) {
                e.printStackTrace();
            }
        } else {
            Log.d("SMC", "PasswordKey and Message can't be NULL");
        }
    }

    @Override
    public void clear(String key) {

    }

    @Override
    public void erase() {

    }

    @Override
    public String get(String key) {

        try {
            SecureCell sc = new SecureCell(key.getBytes(StandardCharsets.UTF_8), MODE_SEAL);

        } catch (InvalidArgumentException e) {
            e.printStackTrace();
        }
        return null;
    }
}
