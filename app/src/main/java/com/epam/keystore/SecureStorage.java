package com.epam.keystore;

import com.epam.keystore.core.SecureStorageException;
import com.epam.keystore.core.SensitiveInfoModule;

import java.security.KeyStoreException;

public class SecureStorage {
    private SensitiveInfoModule versionStrategy;

    public void setStrategy(SensitiveInfoModule strategy) {
        this.versionStrategy = strategy;
    }

    public void save(String key, String value) throws SecureStorageException {
        versionStrategy.save(key, value);
    }

    public String get(String key) throws SecureStorageException {
        return versionStrategy.get(key);
    }

    public void clear(String key) {
        versionStrategy.clear(key);
    }

    public void erase() throws KeyStoreException {
        versionStrategy.erase();
    }
}
