# Android-Secure-Storage
Secure android storage to keep private information safe without requiring a password or a fingerprint.

In order to use the storage do the following: 

```kotlin
storage = new SecureStorage();
if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
   storage.setStrategy(new SafeStorageM(context));
} else
   storage.setStrategy(new SafeStoragePreM(context));
            
```

Then you can save and read the data: 

```kotlin

storage.save(key, password);
val password = storage.get(key);

```

Also, if you have android version > 27 you can implement own strategy for work with KeyStore.
