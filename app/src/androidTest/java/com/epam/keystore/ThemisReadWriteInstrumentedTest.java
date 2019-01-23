package com.epam.keystore;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.epam.keystore.core.SecurityProvider;

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
public class ThemisReadWriteInstrumentedTest {
    private SecureStorage storage;

    @Before
    public void before() {
        Context context = InstrumentationRegistry.getTargetContext();
        storage = new SecureStorage(context, SecurityProvider.Type.THEMIS);
    }

    @Test
    public void shouldGetNullValueIfNotSet() {
        String value = storage.get("blabla");
        assertNull(value);
    }

    @Test
    public void shouldSaveValue() {
        storage.save("key", "passWORD");
        assertEquals("passWORD", storage.get("key"));
    }

    @Test
    public void shouldSaveOtherKeyValue() {
        storage.save("key1", "passWORD");
        assertEquals("passWORD", storage.get("key1"));
    }

    @Test
    public void shouldSaveOtherKeyValue2() {
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
    public void shouldClearStorage() {
        storage.save("key12", "1");
        assertEquals("1", storage.get("key12"));
        storage.remove("key12");
        assertNull(storage.get("key12"));
    }

    @Test
    public void shouldEraseValues() {
        storage.save("key123", "12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry");
        assertEquals("12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry", storage.get("key123"));
        storage.erase();
        assertNotEquals("12093qqwoiejqow812312312123poqj[ 9wpe7nrpwiercwe9rucpn[w9e7rnc;lwiehr pb8ry", storage.get("key123"));
        assertNull(storage.get("key123"));
    }

    @Test
    public void shouldReturnNullIfNoKeyWithWhitespaces() {
        assertNull(storage.get("bad key"));
    }

    @Test
    public void shouldSaveValueForKeyWithWhitespaces() {
        storage.save("KEY", "@");
        assertNull(storage.get("bad key"));
    }

    @Test
    public void shouldClearForKey() {
        storage.save("KEY", "@");
        storage.remove("KEY");
        assertNull(storage.get("KEY"));
    }

    @Test
    public void shouldClearKeys() {
        storage.save("KEY", "1");
        storage.save("KEY2", "2");
        storage.remove("KEY");
        assertEquals("2", storage.get("KEY2"));
        storage.erase();
        assertNull(storage.get("KEY2"));
    }
}
