
# Android-Secure-Storage  
**SecureStorage** is used to keep private information in a safe mode without requiring a password or a fingerprint.  
There are two types of encryption providers:  CIPHER and [THEMIS](https://github.com/cossacklabs/themis). Which provide different level of encryption. 
*THEMIS is stronger then CIPHER and should be used to keep sensitive data like passwords and etc.*

## KOTLIN

**1. In order to initialize the SecureStorage choose one of the following encryption providers:** 
  
**CIPHER** encryption:  
```kotlin  
val storage = new SecureStorage(context, SecurityProvider.Type.CIPHER)  
  ```  
  
**THEMIS** encryption:  
```kotlin  
val storage = new SecureStorage(context, SecurityProvider.Type.THEMIS)  
  ```  
  
  **SecureStorage EVENTS**:  
To subscribe to SecureStorage Events, please initialize  in the following way 

  ```kotlin  
val storage = SecureStorage(context, SecurityProvider.Type.CIPHER, object : SecureStorageCallback {  
    override fun onComplete(actionType: SecureStorageCallback.ActionType) {  
        Log.d("CIPHER_PROVIDER", actionType.toString())  
    }  
   override fun onError(actionType: SecureStorageCallback.ActionType, e: Exception) {  
        Log.d("CIPHER_PROVIDER_ERROR", actionType.toString(), e)  
    }  
})
  ```  
  
**2. Main methods to work with the SecureStorage**
To **SAVE** data:   
  
```kotlin  
storage.save(key, value)  
```  
To **GET**  data:   
  
```kotlin  
storage.get(key)  
``` 
To **REMOVE** specific data:   
  
```kotlin  
storage.remove(key)  
``` 
To **ERASE** all data:   
  
```kotlin  
storage.erase()  
```

## JAVA

**1. In order to initialize the SecureStorage choose one of the following encryption providers:** 
  
**CIPHER** encryption:  
```java  
SecureStorage storage = new SecureStorage(context, SecurityProvider.Type.CIPHER);  
  ```  
  
**THEMIS** encryption:  
```java  
SecureStorage storage = new SecureStorage(context, SecurityProvider.Type.THEMIS);  
  ```  
  
  **SecureStorage EVENTS**:  
To subscribe to SecureStorage Events, please initialize  in the following way 

  ```java  
SecureStorage storage = new SecureStorage(this, SecurityProvider.Type.CIPHER, new SecureStorageCallback() {  
    @Override  
  public void onComplete(ActionType actionType) {  
        if(actionType == ActionType.SAVE){  
            Log.d("CIPHER_PROVIDER", actionType.toString());   
        }  
    }  
  
   @Override  
  public void onError(ActionType actionType, Exception e) { 
     if(actionType == ActionType.SAVE){  
        Log.d("CIPHER_PROVIDER_ERROR", actionType.toString(), e); 
        } 
    }  
});
  ```  
  
**2. Main methods to work with the SecureStorage**
To **SAVE** data:   
  
```java  
storage.save(key, value)  
```  
To **GET**  data:   
  
```java  
storage.get(key)  
``` 
To **REMOVE** specific data:   
  
```java  
storage.remove(key)  
``` 
To **ERASE** all data:   
  
```java  
storage.erase()  
```
