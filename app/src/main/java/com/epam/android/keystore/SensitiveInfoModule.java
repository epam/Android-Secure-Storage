package com.epam.android.keystore;

import java.security.KeyStoreException;

public interface SensitiveInfoModule {

    void save(String key, String value) throws SecureStorageException;

    void clear(String key);

    void erase() throws KeyStoreException;

    String get(String key) throws SecureStorageException;
}
