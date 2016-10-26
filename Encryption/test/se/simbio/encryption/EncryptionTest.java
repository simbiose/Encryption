package se.simbio.encryption;

import junit.framework.TestCase;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import third.part.android.util.Base64;

public class EncryptionTest extends TestCase {

    private final CountDownLatch mSignal = new CountDownLatch(1);

    public void test_commonCase() {
        Encryption encryption = Encryption.getDefault("JustAKey", "some_salt", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
        assertNotNull(encryption);
        String secretText = "Text to be encrypt";
        String encrypted = encryption.encryptOrNull(secretText);
        assertNotNull(encrypted);
        String decrypted = encryption.decryptOrNull(encrypted);
        assertNotNull(decrypted);
        assertEquals(secretText, decrypted);
    }

    public void test_randomText() {
        String key = "$3creTQei";
        String salt = "anotherS@lt";
        byte[] iv = { -21, 58, 41, 124, -17, -19, 47, -35, 115, 120, -41, -7, 127, 103, -91, 8 };
        Encryption encryption = Encryption.getDefault(key, salt, iv);
        assertNotNull(encryption);
        Random random = new Random();
        int textSize = random.nextInt(1000);
        StringBuilder stringBuilder = new StringBuilder();
        do {
            stringBuilder.append((char) (random.nextInt(26) + 'a'));
            textSize--;
        } while (textSize > 0);
        String textToEncrypt = stringBuilder.toString();
        String encryptedText = encryption.encryptOrNull(textToEncrypt);
        assertNotNull(encryptedText);
        String decryptedText = encryption.decryptOrNull(encryptedText);
        assertNotNull(decryptedText);
        assertEquals(decryptedText, textToEncrypt);
    }

    public void test_differentInstances() {
        String key = "yekIsKeyInverted";
        String salt = "tlAsIsSaltInverted";
        byte[] iv = { 79, 71, 80, 66, 55, -109, 20, 30, -49, 105, 4, 59, 98, -70, -77, -61 };
        Encryption encryptEncryption = Encryption.getDefault(key, salt, iv);
        assertNotNull(encryptEncryption);
        String textToEncrypt = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit.";
        String encryptedText = encryptEncryption.encryptOrNull(textToEncrypt);
        assertNotNull(encryptedText);
        Encryption decryptEncryption = Encryption.getDefault(key, salt, iv);
        assertNotNull(decryptEncryption);
        String decryptedText = decryptEncryption.decryptOrNull(encryptedText);
        assertNotNull(decryptedText);
        assertEquals(decryptedText, textToEncrypt);
    }

    public void test_backgroundMode() throws Throwable {
        final String key = "£øЯ€µ%!þZµµ";
        final String salt = "background_S_al_t";
        final byte[] iv = { -89, -19, 17, -83, 86, 106, -31, 30, -5, -111, 61, -75, -84, 95, 120, -53 };
        Encryption encryptEncryption = Encryption.getDefault(key, salt, iv);
        assertNotNull(encryptEncryption);
        final String textToEncrypt = "Just a text that will be encrypted in background.";
        encryptEncryption.encryptAsync(textToEncrypt, new Encryption.Callback() {
            @Override
            public void onSuccess(String encryptedText) {
                Encryption decryptEncryption = Encryption.getDefault(key, salt, iv);
                assertNotNull(decryptEncryption);

                decryptEncryption.decryptAsync(encryptedText, new Encryption.Callback() {
                    @Override
                    public void onSuccess(String decryptedText) {
                        assertEquals(decryptedText, textToEncrypt);
                        mSignal.countDown();
                    }

                    @Override
                    public void onError(Exception exception) {
                        fail(String.format("fail at background decrypt: %s", exception.getMessage()));
                    }
                });
            }

            @Override
            public void onError(Exception exception) {
                fail(String.format("fail at background encrypt: %s", exception.getMessage()));
            }
        });
        mSignal.await(10, TimeUnit.SECONDS);
    }

    public void test_builder() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Encryption encryption = new Encryption.Builder()
                .setKeyLength(128)
                .setKeyAlgorithm("AES")
                .setCharsetName("UTF8")
                .setIterationCount(65536)
                .setKey("mor€Z€cr€tKYss")
                .setDigestAlgorithm("SHA1")
                .setSalt("A beautiful salt")
                .setBase64Mode(Base64.DEFAULT)
                .setAlgorithm("AES/CBC/PKCS5Padding")
                .setSecureRandomAlgorithm("SHA1PRNG")
                .setSecretKeyType("PBKDF2WithHmacSHA1")
                .setIv(new byte[] { 29, 88, -79, -101, -108, -38, -126, 90, 52, 101, -35, 114, 12, -48, -66, -30 })
                .build();
        assertNotNull(encryption);
        String textToEncrypt = "A text to builder test.";
        String encryptedText = encryption.encrypt(textToEncrypt);
        assertNotNull(encryptedText);
        String decryptedText = encryption.decrypt(encryptedText);
        assertNotNull(decryptedText);
        assertEquals(decryptedText, textToEncrypt);
    }

}
