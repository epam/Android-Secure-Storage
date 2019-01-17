package com.epam.keystore.core;

import java.security.KeyStoreException;

public interface SensitiveInfoModule {

    String ANDROID_KEY_STORE = "AndroidKeyStore";

    String KEY_ALIAS = "aliaskeystore";

    void save(String key, String value) throws SecureStorageException;

    void clear(String key);

    void erase() throws KeyStoreException;

    String get(String key) throws SecureStorageException;
}
