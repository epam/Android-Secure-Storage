package com.epam.keystore;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.epam.keystore.providers.cipher.CipherProvider;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;

/**
 * Instrumented test, which will execute on an Android device.
 * This test need launch in two devices for 18 - 22 and 23-27 version API
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class StorageReadWriteInstrumentedTest {
    Context context;
    SecureStorage storage;

    @Before
    public void before() throws Exception {
        context = InstrumentationRegistry.getTargetContext();
        storage = new SecureStorage();
        storage.setSecurityProvider(new CipherProvider(context));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentException() throws Exception {
        storage.get(null);
    }

    @Test
    public void shouldGetNullValueIfNotSet() throws Exception {
        String value = storage.get("blabla");
        assertEquals(null, value);
    }

    @Test
    public void shouldSaveValue() throws Exception {
        storage.save("key", "passWORD");
        assertEquals("passWORD", storage.get("key"));
    }

    @Test
    public void shouldSaveOtherKeyValue() throws Exception {
        storage.save("key1", "passWORD");
        assertEquals("passWORD", storage.get("key1"));
    }

    @Test
    public void shouldSaveOtherKeyValue2() throws Exception {
        storage.save("key1", "passWORD");
        assertEquals("passWORD", storage.get("key1"));
        storage.save("key2", "passWORD");
        assertEquals("passWORD", storage.get("key2"));
        assertEquals("passWORD", storage.get("key1"));
        storage.get("key1");
        assertEquals("passWORD", storage.get("key2"));
        assertEquals("passWORD", storage.get("key1"));
    }

    @Test
    public void shouldClearStorage() throws Exception {
        storage.save("key12", "1");
        assertEquals("1", storage.get("key12"));
        storage.clear("key12");
        assertNull(storage.get("key12"));
    }

    @Test
    public void shouldEraseValues() throws Exception {
        storage.save("key123", "12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry");
        assertEquals("12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry", storage.get("key123"));
        storage.erase();
        assertNotEquals("12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry", storage.get("key123"));
        assertEquals(null, storage.get("key123"));
    }

    @Test
    public void shouldReturnNullIfNoKeyWithWhitespaces() throws Exception {
        assertEquals(null, storage.get("bad key"));
    }

    @Test
    public void shouldSaveValueForKeyWithWhitespaces() throws Exception {
        storage.save("KEY", "@");
        assertEquals(null, storage.get("bad key"));
    }

    @Test
    public void shouldClearForKey() throws Exception {
        storage.save("KEY", "@");
        storage.clear("KEY");
        assertEquals(null, storage.get("KEY"));
    }

    @Test
    public void shouldClearKeys() throws Exception {
        storage.save("KEY", "1");
        storage.save("KEY2", "2");
        storage.clear("KEY");
        assertEquals("2", storage.get("KEY2"));
        storage.erase();
        assertEquals(null, storage.get("KEY2"));
    }
}
