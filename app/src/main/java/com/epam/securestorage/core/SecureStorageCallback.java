package com.epam.securestorage.core;

/**
 * <h2>Operation status Callback</h2>
 * <b>Description:</b>
 * Informs subscribers about operations status
 *
 * @author Denys Mokhrin
 */
public interface SecureStorageCallback {

    enum ActionType {SAVE, GET, REMOVE, ERASE}

    void onComplete(ActionType actionType);

    void onError(ActionType actionType, Exception e);
}
