package com.epam.android.keystore;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.security.KeyPairGeneratorSpec;
import android.support.annotation.Nullable;
import android.util.Base64;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
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
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import static com.epam.android.keystore.SecureStorage.ANDROID_KEY_STORE;
import static com.epam.android.keystore.SecureStorage.KEY_ALIAS;

public class SafeStoragePreM implements SensitiveInfoModule {

    private KeyStore keyStore;
    private static final String CIPHER_TYPE = "RSA/ECB/PKCS1Padding";
    private static final String CIPHER_PROVIDER = "AndroidOpenSSL";

    private SharedPreferences preferences;

    public SafeStoragePreM(Context context) throws InvalidAlgorithmParameterException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
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

    @Override
    public void save(String key, String value) throws SecureStorageException {
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
            throw new SecureStorageException("Error save or cypher value to the storage");
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
    public void erase() throws KeyStoreException {
        keyStore.deleteEntry(KEY_ALIAS);
    }

    private String getPref(String key) {
        return preferences.getString(key, "");
    }

    @Nullable
    @Override
    public String get(String key) throws SecureStorageException {
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
            throw new SecureStorageException("Error get value from the storage");
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
