package com.epam.keystore.core;

public interface SecurityProvider {

    enum Type {
        CIPHER,
        THEMIS
    }

    void save(String key, String value);

    void remove(String key);

    void erase();

    String get(String key);

}
