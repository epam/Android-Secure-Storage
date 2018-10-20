package com.epam.android.keystore;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static com.epam.android.keystore.SecureStorage.ANDROID_KEY_STORE;
import static com.epam.android.keystore.SecureStorage.KEY_ALIAS;

public class SafeStorageM implements SensitiveInfoModule {

    private static final java.lang.String AESGCMNOPADDING = "AES/CBC/PKCS7Padding";
    private static final String I_VECTOR = "valueV";
    private SecretKey secretKey;
    private Cipher cipher;
    private SharedPreferences preferences;
    private KeyStore keyStore;

    @RequiresApi(api = Build.VERSION_CODES.M)
    public SafeStorageM(Context context) throws Exception {
        cipher = Cipher.getInstance(AESGCMNOPADDING);
        secretKey = initSecretKey(KEY_ALIAS);
        preferences = PreferenceManager.getDefaultSharedPreferences(context);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public SafeStorageM(SharedPreferences preferences) throws Exception {
        cipher = Cipher.getInstance(AESGCMNOPADDING);
        secretKey = initSecretKey(KEY_ALIAS);
        this.preferences = preferences;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private SecretKey generatorKey(String alias) throws Exception {
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec
                .Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build();
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
        keyGenerator.init(keyGenParameterSpec);
        return keyGenerator.generateKey();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private SecretKey initSecretKey(String alias) throws Exception {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        if (keyStore.containsAlias(alias)) {
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, null);
            return secretKeyEntry.getSecretKey();
        } else {
            return generatorKey(alias);
        }
    }

    @Override
    public void erase() throws KeyStoreException {
        keyStore.deleteEntry(KEY_ALIAS);
    }

    @Override
    public void save(String key, String password) throws SecureStorageException {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            putPref(I_VECTOR + key, Arrays.toString(cipher.getIV()));
            byte[] encryption = cipher.doFinal(password.getBytes("UTF-8"));
            String encryptedBase64Encoded = Base64.encodeToString(encryption, Base64.DEFAULT);
            putPref(key, encryptedBase64Encoded);
        } catch (InvalidKeyException | IOException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            throw new SecureStorageException("Error save or cypher value to the storage");
        }
    }

    @Override
    public void clear(String key) {
        preferences.edit().remove(key).apply();
    }

    @Nullable
    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public String get(String key) throws SecureStorageException {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key should not be null or empty");
        }

        if (!isSet(I_VECTOR + key) || !isSet(key)) {
            return null;
        }

        try {
            String value = getPref(key);
            byte[] iv = getByteArray(getPref(I_VECTOR + key));
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
            if (secretKeyEntry == null) return null;
            cipher.init(Cipher.DECRYPT_MODE, secretKeyEntry.getSecretKey(), ivParameterSpec);
            if (value.isEmpty()) return null;
            return new String(cipher.doFinal(Base64.decode(value, Base64.DEFAULT)), StandardCharsets.UTF_8);
        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            e.printStackTrace();
            throw new SecureStorageException("Error get value from the storage");
        }
    }

    @Nullable
    private byte[] getByteArray(String stringArray) {
        if (stringArray != null) {
            String[] split = stringArray.substring(1, stringArray.length() - 1).split(", ");
            byte[] array = new byte[split.length];
            for (int i = 0; i < split.length; i++) {
                array[i] = Byte.parseByte(split[i]);
            }
            return array;
        } else
            return null;
    }

    private boolean isSet(String key) {
        return preferences.contains(key);
    }

    private String getPref(String key) {
        return preferences.getString(key, "");
    }

    private void putPref(String key, String value) {
        preferences.edit().putString(key, value).apply();
    }

}
