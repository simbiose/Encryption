package se.simbio.encryption;

import android.test.InstrumentationTestCase;
import android.util.Log;

import java.util.Random;

import se.simbio.encryption.Encryption;

public class EncryptionTest extends InstrumentationTestCase {

    private static final String TAG = "EncryptionTest";

    public void testEncryption() {
        Encryption encryption = new Encryption();
        assertNotNull(encryption);

        Random random = new Random();
        int textSize = random.nextInt(1000);
        StringBuilder stringBuilder = new StringBuilder();
        do {
            stringBuilder.append((char) (random.nextInt(26) + 'a'));
            textSize--;
        } while (textSize > 0);

        String textToEncrypt = stringBuilder.toString();
        String encryptKey = "Some Key";
        Log.d(TAG, String.format("Text to encrypt: %s", textToEncrypt));

        String encryptedText = encryption.encrypt(encryptKey, textToEncrypt);
        Log.d(TAG, String.format("Text encrypted: %s", encryptedText));
        assertNotNull(encryptedText);

        String decryptedText = encryption.decrypt(encryptKey, encryptedText);
        Log.d(TAG, String.format("Text decrypted: %s", decryptedText));
        assertNotNull(decryptedText);
        assertEquals(decryptedText, textToEncrypt);
    }

    public void testEncryptionAgain() {
        Encryption encryption = new Encryption();
        assertNotNull(encryption);

        String textToEncrypt = "Top Secret Text";
        String encryptKey = "Other Key";
        Log.d(TAG, String.format("Text to encrypt: %s", textToEncrypt));

        String encryptedText = encryption.encrypt(encryptKey, textToEncrypt);
        Log.d(TAG, String.format("Text encrypted: %s", encryptedText));
        assertNotNull(encryptedText);

        String decryptedText = encryption.decrypt(encryptKey, encryptedText);
        Log.d(TAG, String.format("Text decrypted: %s", decryptedText));
        assertNotNull(decryptedText);
        assertEquals(decryptedText, textToEncrypt);
    }

}
