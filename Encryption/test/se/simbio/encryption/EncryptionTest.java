/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
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

    @Override
    public void setUp() throws Exception {
        Logger.enableDefaultLog();
    }

    @Override
    public void tearDown() throws Exception {
        Logger.disableLog();
    }

    public void testNormalCase() {
        Encryption encryption = Encryption.getDefault("JustAKey", "some_salt", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
        assertNotNull(encryption);

        String secretText = "Text to be encrypt";
        Logger.log(String.format("Text to encrypt: %s", secretText));

        String encrypted = encryption.encryptOrNull(secretText);
        Logger.log(String.format("Text encrypted: %s", encrypted));
        assertNotNull(encrypted);

        String decrypted = encryption.decryptOrNull(encrypted);
        Logger.log(String.format("Text decrypted: %s", decrypted));
        assertNotNull(decrypted);

        assertEquals(secretText, decrypted);
    }

    public void testLowIteration() {
        Encryption encryption = Encryption.getLowIteration("JustAKey", "great_salt", new byte[] { -7, -6, -5, -4, -3, -2, -1, 0, 0, 1, 2, 3, 4, 5, 6, 7 });
        assertNotNull(encryption);

        String secretText = "Text to be encrypt";
        Logger.log(String.format("Text to encrypt: %s", secretText));

        String encrypted = encryption.encryptOrNull(secretText);
        Logger.log(String.format("Text encrypted: %s", encrypted));
        assertNotNull(encrypted);

        String decrypted = encryption.decryptOrNull(encrypted);
        Logger.log(String.format("Text decrypted: %s", decrypted));
        assertNotNull(decrypted);

        assertEquals(secretText, decrypted);
    }

    public void testEncryptionWithRandomText() {
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
        Logger.log(String.format("Text to encrypt: %s", textToEncrypt));

        String encryptedText = encryption.encryptOrNull(textToEncrypt);
        Logger.log(String.format("Text encrypted: %s", encryptedText));
        assertNotNull(encryptedText);

        String decryptedText = encryption.decryptOrNull(encryptedText);
        Logger.log(String.format("Text decrypted: %s", decryptedText));
        assertNotNull(decryptedText);

        assertEquals(decryptedText, textToEncrypt);
    }

    public void testEncryptionWithDifferentInstances() {
        String key = "yekIsKeyInverted";
        String salt = "tlAsIsSaltInverted";
        byte[] iv = { 79, 71, 80, 66, 55, -109, 20, 30, -49, 105, 4, 59, 98, -70, -77, -61 };

        Encryption encryptEncryption = Encryption.getDefault(key, salt, iv);
        assertNotNull(encryptEncryption);

        String textToEncrypt = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit.";
        Logger.log(String.format("Text to encrypt: %s", textToEncrypt));

        String encryptedText = encryptEncryption.encryptOrNull(textToEncrypt);
        Logger.log(String.format("Text encrypted: %s", encryptedText));
        assertNotNull(encryptedText);

        Encryption decryptEncryption = Encryption.getDefault(key, salt, iv);
        assertNotNull(decryptEncryption);

        String decryptedText = decryptEncryption.decryptOrNull(encryptedText);
        Logger.log(String.format("Text decrypted: %s", decryptedText));
        assertNotNull(decryptedText);

        assertEquals(decryptedText, textToEncrypt);
    }

    public void testBackground() throws Throwable {
        final String key = "£øЯ€µ%!þZµµ";
        final String salt = "background_S_al_t";
        final byte[] iv = { -89, -19, 17, -83, 86, 106, -31, 30, -5, -111, 61, -75, -84, 95, 120, -53 };

        Encryption encryptEncryption = Encryption.getDefault(key, salt, iv);
        assertNotNull(encryptEncryption);

        final String textToEncrypt = "Just a text that will be encrypted in background.";
        Logger.log(String.format("Text to encrypt in background: %s", textToEncrypt));

        encryptEncryption.encryptAsync(textToEncrypt, new Encryption.Callback() {
            @Override
            public void onSuccess(String encryptedText) {
                Logger.log(String.format("Text encrypted in background: %s", encryptedText));

                Encryption decryptEncryption = Encryption.getDefault(key, salt, iv);
                assertNotNull(decryptEncryption);

                decryptEncryption.decryptAsync(encryptedText, new Encryption.Callback() {
                    @Override
                    public void onSuccess(String decryptedText) {
                        Logger.log(String.format("Text decrypted in background: %s", decryptedText));
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
        mSignal.await(10, TimeUnit.MINUTES);
    }

    public void testWithoutSugars() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
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
        Logger.log(String.format("Text to encrypt: %s", textToEncrypt));

        String encryptedText = encryption.encrypt(textToEncrypt);
        Logger.log(String.format("Text encrypted: %s", encryptedText));
        assertNotNull(encryptedText);

        String decryptedText = encryption.decrypt(encryptedText);
        Logger.log(String.format("Text decrypted: %s", decryptedText));
        assertNotNull(decryptedText);

        assertEquals(decryptedText, textToEncrypt);
    }

}
