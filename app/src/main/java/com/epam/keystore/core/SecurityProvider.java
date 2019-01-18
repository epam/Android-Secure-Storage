package com.epam.keystore.core;

public interface SecurityProvider {

    enum Type {
        CIPHER,
        THEMIS
    }

    void save(String key, String value);

    void clear(String key);

    void erase();

    String get(String key);

}
