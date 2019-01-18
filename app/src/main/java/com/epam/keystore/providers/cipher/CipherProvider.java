package com.epam.keystore.providers.cipher;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.Nullable;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import com.epam.keystore.core.SecurityProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;

import static com.epam.keystore.core.KeyStoreHelper.ANDROID_KEY_STORE;
import static com.epam.keystore.core.KeyStoreHelper.KEY_ALIAS;

public class CipherProvider implements SecurityProvider {

    SecurityProvider securityProvider;

    public CipherProvider(Context context) throws Exception {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            // storage.setSecurityProvider(new SafeStorageM(this));
            securityProvider = new CipherM(context);
        } else {
            //storage.setSecurityProvider(new SafeStoragePreM(this));
            securityProvider = new CipherPreM(context);
        }
    }

    @Override
    public void save(String key, String value) {
        securityProvider.save(key, value);
    }

    @Override
    public void clear(String key) {
        securityProvider.clear(key);
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

        public CipherPreM(Context context) throws InvalidAlgorithmParameterException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
            preferences = PreferenceManager.getDefaultSharedPreferences(context);
            initKeyStore(context);
        }

        private void initKeyStore(Context context) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            // Generate the RSA key pairs
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                // Generate a key pair for encryption
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 1);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(KEY_ALIAS)
                        .setSubject(new X500Principal("CN=" + KEY_ALIAS + ", O=Android Authority , C=COMPANY"))
                        .setSerialNumber(BigInteger.TEN)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", ANDROID_KEY_STORE);
                kpg.initialize(spec);
                kpg.generateKeyPair();
            }
        }

        public void save(String key, String value) {
            try {
                KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
                // Encrypt the text
                Cipher inputCipher = Cipher.getInstance(CIPHER_TYPE, CIPHER_PROVIDER);
                inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
                cipherOutputStream.write(value.getBytes("UTF-8"));
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
        public void clear(String key) {
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
                return new String(bytes, "UTF-8");
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
        public CipherM(Context context) throws Exception {
            cipher = Cipher.getInstance(AESGCMNOPADDING);
            secretKey = initSecretKey(KEY_ALIAS);
            preferences = PreferenceManager.getDefaultSharedPreferences(context);
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
                byte[] encryption = cipher.doFinal(password.getBytes("UTF-8"));
                String encryptedBase64Encoded = Base64.encodeToString(encryption, Base64.DEFAULT);
                putPref(key, encryptedBase64Encoded);
            } catch (InvalidKeyException | IOException | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void clear(String key) {
            preferences.edit().remove(key).apply();
        }

        @Nullable
        @RequiresApi(api = Build.VERSION_CODES.M)
        @Override
        public String get(String key) {
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
}
