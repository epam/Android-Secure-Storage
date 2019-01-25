package com.epam.keystore.providers.cipher;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import com.epam.keystore.core.KeyStoreHelper;
import com.epam.keystore.core.SecureStorageCallback;
import com.epam.keystore.core.SecureStorageException;
import com.epam.keystore.core.SecurityProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static com.epam.keystore.core.KeyStoreHelper.KEY_ALIAS;
import static com.epam.keystore.core.SecureStorageCallback.ActionType.ERASE;
import static com.epam.keystore.core.SecureStorageCallback.ActionType.GET;
import static com.epam.keystore.core.SecureStorageCallback.ActionType.REMOVE;
import static com.epam.keystore.core.SecureStorageCallback.ActionType.SAVE;

/**
 * <h2>Cipher encryption provider class</h2>
 * <b>Description:</b>
 * Encryption provider which logic is based on a Cipher
 * Java Cipher implementation. Encapsulates two realizations
 * for M and PreM Android OS versions
 */
public class CipherEncryptionProvider implements SecurityProvider {

    private SecurityProvider securityProvider;
    private SecureStorageCallback callback;

    public CipherEncryptionProvider(Context context, SecureStorageCallback callback) {
        if (callback != null) {
            this.callback = callback;
        }
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            securityProvider = new CipherM(context);
        } else {
            securityProvider = new CipherPreM(context);
        }
    }

    @Override
    public void save(String key, String value) {
        securityProvider.save(key, value);
    }

    @Override
    public void remove(String key) {
        securityProvider.remove(key);
    }

    @Override
    public void erase() {
        securityProvider.erase();
    }

    @Override
    public String get(String key) {
        return securityProvider.get(key);
    }

    //Uniq key need to be provided to avoid Key collision in case if two providers
    //are used at the same app
    private String generateKeyWithPrefix(String key) {
        key.trim();
        return Type.CIPHER.toString() + key;
    }

    class CipherPreM implements SecurityProvider {
        private KeyStore keyStore;
        private static final String CIPHER_TYPE = "RSA/ECB/PKCS1Padding";
        private static final String CIPHER_PROVIDER = "AndroidOpenSSL";

        private SharedPreferences preferences;

        CipherPreM(Context context) {
            preferences = PreferenceManager.getDefaultSharedPreferences(context);
            try {
                keyStore = KeyStoreHelper.getKeyStorePreM(context);
            } catch (InvalidAlgorithmParameterException | KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void save(@NonNull String key, @NonNull String value) {
            if (key == null || value == null || key.isEmpty() || value.isEmpty()) {
                if (callback != null) {
                    callback.onError(SAVE, new SecureStorageException("Key or Value can't be NULL or empty"));
                }
                return;
            }

            try {
                key = generateKeyWithPrefix(key);

                KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
                // Encrypt the text
                Cipher inputCipher = Cipher.getInstance(CIPHER_TYPE, CIPHER_PROVIDER);
                inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
                cipherOutputStream.write(value.getBytes(StandardCharsets.UTF_8));
                cipherOutputStream.close();

                byte[] cryptoText = outputStream.toByteArray();
                String encryptedString = (Base64.encodeToString(cryptoText, Base64.DEFAULT));
                putPref(key, encryptedString);
                outputStream.close();

                if (callback != null) {
                    callback.onComplete(SAVE);
                }
            } catch (NoSuchAlgorithmException | KeyStoreException | InvalidKeyException | IOException | NoSuchPaddingException | UnrecoverableEntryException | NoSuchProviderException e) {
                e.printStackTrace();

                if (callback != null) {
                    callback.onError(SAVE, e);
                }
            }
        }

        private void putPref(String key, String value) {
            preferences.edit().putString(key, value).apply();
        }

        @Override
        public void remove(@NonNull String key) {
            if (key == null || key.isEmpty()) {
                if (callback != null) {
                    callback.onError(REMOVE, new SecureStorageException("Key can't be NULL or empty"));
                }
                return;
            }

            key = generateKeyWithPrefix(key);
            preferences.edit().remove(key).apply();
            if (callback != null) {
                callback.onComplete(REMOVE);
            }
        }

        @Override
        public void erase() {
            try {
                keyStore.deleteEntry(KEY_ALIAS);
                if (callback != null) {
                    callback.onComplete(ERASE);
                }
            } catch (KeyStoreException e) {
                e.printStackTrace();
                if (callback != null) {
                    callback.onError(ERASE, e);
                }
            }
        }

        private String getPref(String key) {
            return preferences.getString(key, "");
        }

        @Nullable
        @Override
        public String get(@NonNull String key) {
            if (key == null || key.isEmpty()) {
                if (callback != null) {
                    callback.onError(GET, new SecureStorageException("Key or Value can't be NULL ot empty"));
                }
                return null;
            }

            key = generateKeyWithPrefix(key);
            KeyStore.PrivateKeyEntry privateKeyEntry;
            try {
                privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);

                if (privateKeyEntry == null) return null;
                Cipher cipher = Cipher.getInstance(CIPHER_TYPE, CIPHER_PROVIDER);
                cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());

                String value = getPref(key);
                if (value.isEmpty()) return null;
                byte[] bytes = getBytes(cipher, value);
                String result = new String(bytes, StandardCharsets.UTF_8);

                if (callback != null) {
                    callback.onComplete(GET);
                }

                return result;
            } catch (NoSuchAlgorithmException | KeyStoreException | InvalidKeyException | IOException | NoSuchPaddingException | UnrecoverableEntryException | NoSuchProviderException e) {
                e.printStackTrace();
                if (callback != null) {
                    callback.onError(GET, e);
                }
                return null;
            }
        }

        private byte[] getBytes(Cipher cipher, String value) throws IOException {
            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream((Base64.decode(value, Base64.DEFAULT))), cipher);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }
            return bytes;
        }
    }

    class CipherM implements SecurityProvider {

        private static final java.lang.String AESGCMNOPADDING = "AES/CBC/PKCS7Padding";
        private static final String I_VECTOR = "valueV";
        private SecretKey secretKey;
        private Cipher cipher;
        private SharedPreferences preferences;
        private KeyStore keyStore;

        @RequiresApi(api = Build.VERSION_CODES.M)
        CipherM(Context context) {
            try {
                cipher = Cipher.getInstance(AESGCMNOPADDING);
                keyStore = KeyStoreHelper.getKeyStoreM();
                secretKey = KeyStoreHelper.initSecretKey(KEY_ALIAS);
                preferences = PreferenceManager.getDefaultSharedPreferences(context);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public void erase() {
            try {
                keyStore.deleteEntry(KEY_ALIAS);
                if (callback != null) {
                    callback.onComplete(ERASE);
                }
            } catch (KeyStoreException e) {
                e.printStackTrace();
                if (callback != null) {
                    callback.onError(ERASE, e);
                }
            }
        }

        @Override
        public void save(@NonNull String key, @NonNull String value) {
            if (key == null || value == null || key.isEmpty() || value.isEmpty()) {
                if (callback != null) {
                    callback.onError(SAVE, new SecureStorageException("Key or Value can't be NULL"));
                }
                return;
            }

            key = generateKeyWithPrefix(key);

            try {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                putPref(I_VECTOR + key, Arrays.toString(cipher.getIV()));
                byte[] encryption = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
                String encryptedBase64Encoded = Base64.encodeToString(encryption, Base64.DEFAULT);
                putPref(key, encryptedBase64Encoded);

                if (callback != null) {
                    callback.onComplete(SAVE);
                }
            } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
                if (callback != null) {
                    callback.onError(SAVE, e);
                }
            }
        }

        @Override
        public void remove(@NonNull String key) {
            if (key == null || key.isEmpty()) {
                if (callback != null) {
                    callback.onError(REMOVE, new SecureStorageException("Key can't be NULL or empty"));
                }
                return;
            }

            key = generateKeyWithPrefix(key);
            preferences.edit().remove(key).apply();
            if (callback != null) {
                callback.onComplete(REMOVE);
            }
        }

        @Nullable
        @RequiresApi(api = Build.VERSION_CODES.M)
        @Override
        public String get(@NonNull String key) {
            if (key == null || key.isEmpty()) {
                if (callback != null) {
                    callback.onError(GET, new SecureStorageException("Key can't be NULL or empty"));
                }
                return null;
            }

            key = generateKeyWithPrefix(key);
            if (!isValueSet(I_VECTOR + key) || !isValueSet(key)) {
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
                String result = new String(cipher.doFinal(Base64.decode(value, Base64.DEFAULT)), StandardCharsets.UTF_8);

                if (callback != null) {
                    callback.onComplete(GET);
                }

                return result;
            } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
                e.printStackTrace();

                if (callback != null) {
                    callback.onError(GET, e);
                }
                return null;
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

        private boolean isValueSet(String key) {
            return preferences.contains(key);
        }

        private String getPref(String key) {
            return preferences.getString(key, null);
        }

        private void putPref(String key, String value) {
            preferences.edit().putString(key, value).apply();
        }
    }
}
