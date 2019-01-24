package com.epam.keystore.core;

public interface SecureStorageCallback {

    enum ActionType {SAVE, GET, REMOVE, ERASE}

    void onComplete(ActionType actionType);

    void onError(ActionType actionType, Exception e);
}
