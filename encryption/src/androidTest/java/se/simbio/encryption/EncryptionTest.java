package se.simbio.encryption;

import android.test.InstrumentationTestCase;
import android.util.Log;

import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.spec.IvParameterSpec;

public class EncryptionTest extends InstrumentationTestCase {

    private static final String TAG = "EncryptionTest";

    public void testNormalCase() {
        String key = "$3creTQei";
        String secretText = "Text to be encrypt";

        //this is just a test, you should use a secure IV !!!!
        byte[] iv = {-8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7};
        Encryption encryption = Encryption.getSecureDefault(iv);

        String encrypted = encryption.encrypt(key, secretText);
        String decrypted = encryption.decrypt(key, encrypted);

        Log.d("Encryption", String.format("The text '%s' encrypted with key '%s' is %s", secretText, key, encrypted));
        Log.d("Encryption", String.format("This is the text '%s' decrypted with key '%s' on %s", decrypted, key, encrypted));

        assertEquals(secretText, decrypted);
    }

    public void testEncryptionWithRandomText() {
        Encryption encryption = Encryption.getDefault();
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
        Encryption encryption = Encryption.getDefault();
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
        Encryption encryptEncryption = Encryption.getDefault();
        assertNotNull(encryptEncryption);

        String textToEncrypt = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit.";
        String encryptKey = "£øЯ€µ%!þZµµ";
        Log.d(TAG, String.format("Text to encrypt: %s", textToEncrypt));

        String encryptedText = encryptEncryption.encrypt(encryptKey, textToEncrypt);
        Log.d(TAG, String.format("Text encrypted: %s", encryptedText));
        assertNotNull(encryptedText);

        Encryption decryptEncryption = Encryption.getDefault();
        assertNotNull(decryptEncryption);

        String decryptedText = decryptEncryption.decrypt(encryptKey, encryptedText);
        Log.d(TAG, String.format("Text decrypted: %s", decryptedText));
        assertNotNull(decryptedText);
        assertEquals(decryptedText, textToEncrypt);
    }

    public void testGetterAndSetter() throws Exception {
        Encryption.Builder builder = Encryption.Builder.getDefaultBuilder();
        assertNotNull(builder);

        String charsetName = "charsetName";
        builder.setCharsetName(charsetName);
        assertEquals(charsetName, builder.getCharsetName());

        String algorithm = "algorithm";
        builder.setAlgorithm(algorithm);
        assertEquals(algorithm, builder.getAlgorithm());

        int base64Mode = (int) (Math.random() * Integer.MAX_VALUE);
        builder.setBase64Mode(base64Mode);
        assertEquals(base64Mode, builder.getBase64Mode());

        String secretKeyType = "secretKeyType";
        builder.setSecretKeyType(secretKeyType);
        assertEquals(secretKeyType, builder.getSecretKeyType());

        String salt = "salt";
        builder.setSalt(salt);
        assertEquals(salt, builder.getSalt());

        int keyLength = (int) (Math.random() * Integer.MAX_VALUE);
        builder.setKeyLength(keyLength);
        assertEquals(keyLength, builder.getKeyLength());

        int iterationCount = (int) (Math.random() * Integer.MAX_VALUE);
        builder.setIterationCount(iterationCount);
        assertEquals(iterationCount, builder.getIterationCount());

        String secureRandomAlgorithm = "secureRandomAlgorithm";
        builder.setSecureRandomAlgorithm(secureRandomAlgorithm);
        assertEquals(secureRandomAlgorithm, builder.getSecureRandomAlgorithm());

        String digestAlgorithm = "SHA1";
        builder.setDigestAlgorithm(digestAlgorithm);
        assertEquals(digestAlgorithm, builder.getDigestAlgorithm());

        byte[] iv = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, -1, -2, -3, -4, -5, -6};
        builder.setIv(iv);
        assertEquals(iv.length, builder.getIv().length);
        for (int i = 0; i < iv.length; i++) {
            assertEquals(iv[i], builder.getIv()[i]);
        }

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        builder.setIvParameterSpec(ivParameterSpec);
        assertEquals(ivParameterSpec, builder.getIvParameterSpec());

        builder.setSecureRandomAlgorithm("SHA1PRNG");
        SecureRandom secureRandom = builder.getSecureRandom();
        assertNull(secureRandom);
        builder.build();
        secureRandom = builder.getSecureRandom();
        assertNotNull(secureRandom);
        builder.setSecureRandom(secureRandom);
        assertEquals(secureRandom, builder.getSecureRandom());
    }

}
