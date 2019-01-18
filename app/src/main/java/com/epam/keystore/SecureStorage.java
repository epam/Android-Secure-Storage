package com.epam.keystore;

import com.epam.keystore.core.SecurityProvider;

public class SecureStorage {
    private SecurityProvider securityProvider;

    public void setSecurityProvider(SecurityProvider securityProvider) {
        this.securityProvider = securityProvider;
    }

    public void save(String key, String value) {
        securityProvider.save(key, value);
    }

    public String get(String key) {
        return securityProvider.get(key);
    }

    public void clear(String key) {
        securityProvider.clear(key);
    }

    public void erase() {
        securityProvider.erase();
    }
}
