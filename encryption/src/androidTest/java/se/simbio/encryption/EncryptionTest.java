package se.simbio.encryption;

import android.test.InstrumentationTestCase;
import android.util.Log;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.spec.IvParameterSpec;

public class EncryptionTest extends InstrumentationTestCase {

    private static final String TAG = "EncryptionTest";

    public void testNormalCase() {
        String key = "$3creTQei";
        String secretText = "Text to be encrypt";

        //this is just a test, you should use a secure IV !!!!
        byte[] iv = {-8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7};

        Encryption encryption = new Encryption();
        encryption.setIv(iv);

        String encrypted = encryption.encrypt(key, secretText);
        String decrypted = encryption.decrypt(key, encrypted);

        Log.d("Encryption", String.format("The text '%s' encrypted with key '%s' is %s", secretText, key, encrypted));
        Log.d("Encryption", String.format("This is the text '%s' decrypted with key '%s' on %s", decrypted, key, encrypted));

        assertEquals(secretText, decrypted);
    }

    public void testEncryptionWithRandomText() {
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

    public void testEncryptionWithPredeterminedText() {
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

    public void testEncryptionWithDifferentInstances() {
        Encryption encryptEncryption = new Encryption();
        assertNotNull(encryptEncryption);

        String textToEncrypt = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit.";
        String encryptKey = "£øЯ€µ%!þZµµ";
        Log.d(TAG, String.format("Text to encrypt: %s", textToEncrypt));

        String encryptedText = encryptEncryption.encrypt(encryptKey, textToEncrypt);
        Log.d(TAG, String.format("Text encrypted: %s", encryptedText));
        assertNotNull(encryptedText);

        byte[] iv = encryptEncryption.getIv();
        Log.d(TAG, String.format("The IV: %s", Arrays.toString(iv)));
        assertNotNull(iv);

        Encryption decryptEncryption = new Encryption();
        decryptEncryption.setIv(iv);
        assertNotNull(decryptEncryption);

        String decryptedText = decryptEncryption.decrypt(encryptKey, encryptedText);
        Log.d(TAG, String.format("Text decrypted: %s", decryptedText));
        assertNotNull(decryptedText);
        assertEquals(decryptedText, textToEncrypt);
    }

    public void testGetterAndSetter() throws Exception {
        Encryption encryption = new Encryption();
        assertNotNull(encryption);

        String charsetName = "charsetName";
        encryption.setCharsetName(charsetName);
        assertEquals(charsetName, encryption.getCharsetName());

        String algorithm = "algorithm";
        encryption.setAlgorithm(algorithm);
        assertEquals(algorithm, encryption.getAlgorithm());

        int base64Mode = (int) (Math.random() * Integer.MAX_VALUE);
        encryption.setBase64Mode(base64Mode);
        assertEquals(base64Mode, encryption.getBase64Mode());

        String secretKeyType = "secretKeyType";
        encryption.setSecretKeyType(secretKeyType);
        assertEquals(secretKeyType, encryption.getSecretKeyType());

        String salt = "salt";
        encryption.setSalt(salt);
        assertEquals(salt, encryption.getSalt());

        int keyLength = (int) (Math.random() * Integer.MAX_VALUE);
        encryption.setKeyLength(keyLength);
        assertEquals(keyLength, encryption.getKeyLength());

        int iterationCount = (int) (Math.random() * Integer.MAX_VALUE);
        encryption.setIterationCount(iterationCount);
        assertEquals(iterationCount, encryption.getIterationCount());

        String secureRandomAlgorithm = "secureRandomAlgorithm";
        encryption.setSecureRandomAlgorithm(secureRandomAlgorithm);
        assertEquals(secureRandomAlgorithm, encryption.getSecureRandomAlgorithm());

        encryption.setSecureRandomAlgorithm("SHA1PRNG");
        SecureRandom secureRandom = encryption.getSecureRandom();
        assertNotNull(secureRandom);
        encryption.setSecureRandom(secureRandom);
        assertEquals(secureRandom, encryption.getSecureRandom());

        IvParameterSpec ivParameterSpec = new IvParameterSpec(encryption.generateSecureRandomIv());
        encryption.setIvParameterSpec(ivParameterSpec);
        assertEquals(ivParameterSpec, encryption.getIvParameterSpec());

        byte[] iv = encryption.generateSecureRandomIv();
        encryption.setIv(iv);
        assertEquals(iv.length, encryption.getIv().length);
        for (int i = 0; i < iv.length; i++) {
            assertEquals(iv[i], encryption.getIv()[i]);
        }
    }

}
