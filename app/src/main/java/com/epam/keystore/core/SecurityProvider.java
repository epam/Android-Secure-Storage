package com.epam.keystore.core;

/**
 * <h2>Main encryption manager class</h2>
 * <b>Description:</b>
 *The main interface that generalizeы any encryption
 *implementations.
 *
 * @author Denys Mokhrin
 */
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
