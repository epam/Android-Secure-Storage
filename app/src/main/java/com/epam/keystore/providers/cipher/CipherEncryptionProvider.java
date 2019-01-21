package com.epam.keystore.providers.cipher;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import com.epam.keystore.core.KeyStoreHelper;
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

public class CipherEncryptionProvider implements SecurityProvider {

    private SecurityProvider securityProvider;

    public CipherEncryptionProvider(Context context) throws Exception {
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

    class CipherPreM implements SecurityProvider {
        private KeyStore keyStore;
        private static final String CIPHER_TYPE = "RSA/ECB/PKCS1Padding";
        private static final String CIPHER_PROVIDER = "AndroidOpenSSL";

        private SharedPreferences preferences;

        CipherPreM(Context context) throws InvalidAlgorithmParameterException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
            preferences = PreferenceManager.getDefaultSharedPreferences(context);
            keyStore = KeyStoreHelper.getKeyStorePreM(context);
        }


        public void save(String key, String value) {
            try {
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
            } catch (NoSuchAlgorithmException | KeyStoreException | InvalidKeyException | IOException | NoSuchPaddingException | UnrecoverableEntryException | NoSuchProviderException e) {
                e.printStackTrace();
            }
        }

        private void putPref(String key, String value) {
            preferences.edit().putString(key, value).apply();
        }

        @Override
        public void remove(String key) {
            preferences.edit().remove(key).apply();
        }

        @Override
        public void erase() {
            try {
                keyStore.deleteEntry(KEY_ALIAS);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }

        private String getPref(String key) {
            return preferences.getString(key, "");
        }

        @Nullable
        @Override
        public String get(String key) {
            if (key == null || key.isEmpty()) {
                throw new IllegalArgumentException("Key should not be null or empty");
            }

            KeyStore.PrivateKeyEntry privateKeyEntry;
            try {
                privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);

                if (privateKeyEntry == null) return null;
                Cipher cipher = Cipher.getInstance(CIPHER_TYPE, CIPHER_PROVIDER);
                cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());

                String value = getPref(key);
                if (value.isEmpty()) return null;
                byte[] bytes = getBytes(cipher, value);
                return new String(bytes, StandardCharsets.UTF_8);
            } catch (NoSuchAlgorithmException | KeyStoreException | InvalidKeyException | IOException | NoSuchPaddingException | UnrecoverableEntryException | NoSuchProviderException e) {
                e.printStackTrace();
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
        CipherM(Context context) throws Exception {
            cipher = Cipher.getInstance(AESGCMNOPADDING);
            keyStore = KeyStoreHelper.getKeyStoreM();
            secretKey = KeyStoreHelper.initSecretKey(KEY_ALIAS);
            preferences = PreferenceManager.getDefaultSharedPreferences(context);
        }

        @Override
        public void erase() {
            try {
                keyStore.deleteEntry(KEY_ALIAS);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void save(String key, String password) {
            try {
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                putPref(I_VECTOR + key, Arrays.toString(cipher.getIV()));
                byte[] encryption = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
                String encryptedBase64Encoded = Base64.encodeToString(encryption, Base64.DEFAULT);
                putPref(key, encryptedBase64Encoded);
            } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void remove(String key) {
            preferences.edit().remove(key).apply();
        }

        @Nullable
        @RequiresApi(api = Build.VERSION_CODES.M)
        @Override
        public String get(String key) {
            if (key == null || key.isEmpty()) {
                throw new IllegalArgumentException("Key should not be null or empty");
            }

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
                return new String(cipher.doFinal(Base64.decode(value, Base64.DEFAULT)), StandardCharsets.UTF_8);
            } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
                e.printStackTrace();
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
            return preferences.getString(key, "");
        }

        private void putPref(String key, String value) {
            preferences.edit().putString(key, value).apply();
        }
    }
}
