package com.epam.keystore.core;

public interface SecureStorageCallback {

    void onComplete();

    void onError(Exception e);
}
