package com.epam.keystore;

import android.content.Context;

import com.epam.keystore.core.SecureStorageException;
import com.epam.keystore.core.SecurityProvider;
import com.epam.keystore.core.SecurityProvider.Type;
import com.epam.keystore.providers.cipher.CipherEncryptionProvider;
import com.epam.keystore.providers.themis.ThemisEncryptionProvider;

public class SecureStorage {

    private SecurityProvider securityProvider;

    //TODO: method description
    public SecureStorage(Context context, Type securityProviderType) {
        switch (securityProviderType) {
            case CIPHER:
                if (securityProvider == null) {
                    try {
                        securityProvider = new CipherEncryptionProvider(context);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                break;
            case THEMIS:
                try {
                    securityProvider = new ThemisEncryptionProvider(context);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            default:
                new SecureStorageException("No such provider");
        }
    }

    //TODO: method description
    public void save(String key, String value) {
        if (securityProvider != null) {
            securityProvider.save(key, value);
        } else {
            new SecureStorageException("Provider is not initialized");
        }
    }

    //TODO: method description
    public String get(String key) {
        if (securityProvider != null) {
            return securityProvider.get(key);
        } else {
            new SecureStorageException("Provider is not initialized");
            return null;
        }
    }

    //TODO: method description
    public void clear(String key) {
        if (securityProvider != null) {
            securityProvider.clear(key);
        } else {
            new SecureStorageException("Provider is not initialized");
        }
    }

    //TODO: method description
    public void erase() {
        if (securityProvider != null) {
            securityProvider.erase();
        } else {
            new SecureStorageException("Provider is not initialized");
        }
    }

    //TODO: method description
    public void setCustomSecurityProvider(SecurityProvider provider) {
        this.securityProvider = provider;
    }
}
