package com.epam.demo;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.epam.keystore.SecureStorage;
import com.epam.keystore.core.SecureStorageCallback;
import com.epam.keystore.core.SecurityProvider;


public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initCipherProvider();
        initThemisProvider();
    }

    private void initCipherProvider() {
        final SecureStorage storage = new SecureStorage(this, SecurityProvider.Type.CIPHER, new SecureStorageCallback() {
            @Override
            public void onComplete(ActionType actionType) {
                if(actionType == ActionType.SAVE){
                    Toast.makeText(getBaseContext(), "Has been saved", Toast.LENGTH_SHORT).show();
                }
                Log.d("CIPHER_PROVIDER", actionType.toString());
            }

            @Override
            public void onError(ActionType actionType, Exception e) {
                Toast.makeText(getBaseContext(), "Error on"+ actionType.toString() + " " + e.getLocalizedMessage(), Toast.LENGTH_SHORT).show();
                Log.d("CIPHER_PROVIDER", actionType.toString(), e);
            }
        });

        final EditText valueKey = findViewById(R.id.value_key);
        final EditText valueStore = findViewById(R.id.value_store);
        final TextView anyValue = findViewById(R.id.tv_decrypted_value);

        findViewById(R.id.btn_save).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                storage.save(valueKey.getText().toString(), valueStore.getText().toString());
            }
        });

        findViewById(R.id.btn_get_decrypted_value).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                anyValue.setText(storage.get(valueKey.getText().toString()));
            }
        });

        findViewById(R.id.btn_get_stored_value).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(view.getContext());
                anyValue.setText(prefs.getString(valueKey.getText().toString(), ""));
            }
        });
    }

    private void initThemisProvider() {
        final SecureStorage storage = new SecureStorage(this, SecurityProvider.Type.THEMIS, new SecureStorageCallback() {
            @Override
            public void onComplete(SecureStorageCallback.ActionType actionType) {
                Log.d("THEMIS_PROVIDER", actionType.toString());
            }

            @Override
            public void onError(SecureStorageCallback.ActionType actionType, Exception e) {
                Log.d("THEMIS_PROVIDER", actionType.toString(), e);
            }
        });

        final EditText valueKey = findViewById(R.id.value_key2);
        final EditText valueStore = findViewById(R.id.value_store2);
        final TextView anyValue = findViewById(R.id.tv_decrypted_value2);

        findViewById(R.id.btn_save2).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                storage.save(valueKey.getText().toString(), valueStore.getText().toString());
            }
        });

        findViewById(R.id.btn_get_decrypted_value2).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                anyValue.setText(storage.get(valueKey.getText().toString()));
            }
        });

        findViewById(R.id.btn_get_stored_value2).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(view.getContext());
                anyValue.setText(prefs.getString(valueKey.getText().toString(), ""));
            }
        });
    }
}
