package com.epam.demo;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import com.epam.keystore.SecureStorage;
import com.epam.keystore.providers.cipher.CipherProvider;

import butterknife.BindView;
import butterknife.ButterKnife;

public class MainActivity extends AppCompatActivity {

    @BindView(R.id.tv_decrypted_value)
    TextView tvDecryptedValue;

    @BindView(R.id.tv_stored_value)
    TextView tvStoredValue;

    @BindView(R.id.et_value_to_store)
    EditText etToBeStored;

    private SecureStorage storage;
    private final String TEST_KEY = "com.epam.keystore.keystore.demo.TEST_KEY";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        ButterKnife.bind(this);

        try {
            storage = new SecureStorage();
            storage.setSecurityProvider(new CipherProvider(this));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void saveValue(View view) {
        if (storage != null) {
            storage.save(TEST_KEY, etToBeStored.getText().toString());
        }
    }

    public void getDecryptedValue(View view) {
        if (storage != null) {
            tvDecryptedValue.setText(storage.get(TEST_KEY));
        }
    }

    public void getStoredValue(View view) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        tvStoredValue.setText(prefs.getString(TEST_KEY, ""));
    }

}
