package com.epam.android.keystore;

/**
 * Created by Andrei_Gusenkov on 3/13/2018.
 */

public class SecureStorageException extends Exception {
    public SecureStorageException() { super(); }
    public SecureStorageException(String message) { super(message); }
    public SecureStorageException(String message, Throwable cause) { super(message, cause); }
    public SecureStorageException(Throwable cause) { super(cause); }
}
