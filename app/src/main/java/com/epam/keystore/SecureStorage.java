package com.epam.keystore;

import android.content.Context;
import android.support.annotation.NonNull;

import com.epam.keystore.core.SecurityProvider;
import com.epam.keystore.core.SecurityProvider.Type;
import com.epam.keystore.providers.cipher.CipherEncryptionProvider;
import com.epam.keystore.providers.themis.ThemisEncryptionProvider;

/**
 * <h2>Main encryption manager class</h2>
 * <b>Description:</b>The SecureStorage provides an ability to
 * encrypt/decrypt any data based on K, V logic. To instantiate
 * the class, Context and SecurityProviderType need to be provided.
 * There are two main SecurityProviders: Themis and Cipher.
 *
 * @author Denys Mokhrin
 */
public class SecureStorage {

    private SecurityProvider securityProvider;

    /**
     * Forbids default instance
     */
    private SecureStorage() {
    }

    /**
     * <b>Description:</b> Main method to instantiate SecureStorage
     *
     * @param context              provides app context
     * @param securityProviderType constant value, need to be
     *                             chosen from the enum
     *                             SecurityProvider.Type
     * @return SecureStore Instance
     */
    public SecureStorage(@NonNull Context context, @NonNull Type securityProviderType) {
        initProvider(context, securityProviderType);
    }

    private void initProvider(Context context, Type securityProviderType) {
        if (context != null && securityProviderType != null) {
            switch (securityProviderType) {
                case CIPHER:
                    try {
                        securityProvider = new CipherEncryptionProvider(context);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    break;
                case THEMIS:
                    securityProvider = new ThemisEncryptionProvider(context);
                    break;
            }
        }
    }

    /**
     * <b>Description:</b> Saves data using an encryption algorithm
     *
     * @param key   provides access to store data
     * @param value data that need to be encrypted
     * @return SecureStore Instance
     */
    public void save(String key, String value) {
        if (key != null && value != null) {
            securityProvider.save(key, value);
        }
    }

    /**
     * <b>Description:</b> Returns decrypted data
     *
     * @param key is used to find encrypted data
     * @return Decrypted Data in a String format
     */
    public String get(@NonNull String key) {
        if (key != null) {
            return securityProvider.get(key);
        } else {
            return null;
        }
    }

    /**
     * <b>Description:</b> Returns decrypted data
     *
     * @param key is used to find data for further removal
     */
    public void remove(@NonNull String key) {
        if (key != null) {
            securityProvider.remove(key);
        }
    }

    /**
     * <b>Description:</b> Removes all data from storage
     */
    public void erase() {
        securityProvider.erase();
    }
}
