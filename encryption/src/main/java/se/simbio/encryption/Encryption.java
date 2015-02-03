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

import android.R.string;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A class to make more easy simple encrypt routines
 */
public class Encryption {

    private static final String TAG = "Encryption";

    /**
     * The Builder used too create the Encryption instance
     */
    private Builder mBuilder;

    /**
     * The private constructor, you should use the builder or get the default
     */
    private Encryption(Builder builder) {
        mBuilder = builder;
    }

    /**
     * This method create a default Encryption instance, please consider make your own instance specially with your own IV or uses the getSecureDefault
     *
     * @return an default encryption instance, or <code>null</code> if occur some Exception
     */
    public static Encryption getDefault() {
        return Builder.getDefaultBuilder().build();
    }

    /**
     * @return an default encryption instance with your own iv, or <code>null</code> if occur some Exception
     */
    public static Encryption getSecureDefault(byte[] iv) {
        return Encryption.Builder.getDefaultBuilder().setIv(iv).build();
    }

    /**
     * Encrypt a {@link string}
     *
     * @param key  the {@link String} key
     * @param data the {@link String} to be encrypted
     *
     * @return the encrypted {@link String} or <code>null</code> if occur some error
     */
    public String encrypt(String key, String data) {
        if (key == null || data == null) return null;
        try {
            SecretKey secretKey = getSecretKey(hashTheKey(key));
            byte[] dataBytes = data.getBytes(mBuilder.getCharsetName());
            Cipher cipher = Cipher.getInstance(mBuilder.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, mBuilder.getIvParameterSpec(), mBuilder.getSecureRandom());
            return Base64.encodeToString(cipher.doFinal(dataBytes), mBuilder.getBase64Mode());
        } catch (Exception e) {
            Log.e(TAG, e.toString());
            return null;
        }
    }

    /**
     * Decrypt a {@link string}
     *
     * @param key  the {@link String} key
     * @param data the {@link String} to be decrypted
     *
     * @return the decrypted {@link String} or <code>null</code> if occur some error
     */
    public String decrypt(String key, String data) {
        if (key == null || data == null) return null;
        try {
            byte[] dataBytes = Base64.decode(data, mBuilder.getBase64Mode());
            SecretKey secretKey = getSecretKey(hashTheKey(key));
            Cipher cipher = Cipher.getInstance(mBuilder.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, secretKey, mBuilder.getIvParameterSpec(), mBuilder.getSecureRandom());
            byte[] dataBytesDecrypted = (cipher.doFinal(dataBytes));
            return new String(dataBytesDecrypted);
        } catch (Exception e) {
            Log.e(TAG, e.toString());
            return null;
        }
    }

    /**
     * creates a 128bit salted aes key
     *
     * @param key encoded input key
     *
     * @return aes 128 bit salted key
     *
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeySpecException
     */
    private SecretKey getSecretKey(char[] key) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(mBuilder.getSecretKeyType());
        KeySpec spec = new PBEKeySpec(key, mBuilder.getSalt().getBytes(mBuilder.getCharsetName()), mBuilder.getIterationCount(), mBuilder.getKeyLength());
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), mBuilder.getAlgorithm());
    }

    /**
     * takes in a simple string and performs an sha1 hash
     * that is 128 bits long...we then base64 encode it
     * and return the char array
     *
     * @param key simple inputted string
     *
     * @return sha1 base64 encoded representation
     *
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     */
    private char[] hashTheKey(String key) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(mBuilder.getDigestAlgorithm());
        messageDigest.update(key.getBytes(mBuilder.getCharsetName()));
        return Base64.encodeToString(messageDigest.digest(), Base64.NO_PADDING).toCharArray();
    }

    /**
     * A class to create an Encryption instance
     */
    public static class Builder {

        private byte[] mIv;
        private int mKeyLength;
        private int mBase64Mode;
        private int mIterationCount;
        private String mSalt;
        private String mAlgorithm;
        private String mCharsetName;
        private String mSecretKeyType;
        private String mDigestAlgorithm;
        private String mSecureRandomAlgorithm;
        private SecureRandom mSecureRandom;
        private IvParameterSpec mIvParameterSpec;

        /**
         * @return an default builder with an IV of 16 zeros, you should uses your own secret IV,
         * the default char set is UTF-8
         * the default base mode is Base64
         * the Secret Key Type is the PBKDF2WithHmacSHA1
         * the default salt is "some_salt" but can be anything
         * the default length of key is 128
         * the default iteration count is 65536
         * the default algorithm is AES in CBC mode and PKCS 5 Padding
         * the default secure random algorithm is SHA1PRNG
         * the default message digest algorithm SHA1
         */
        public static Builder getDefaultBuilder() {
            return new Builder()
                    .setKeyLength(128)
                    .setIterationCount(65536)
                    .setSalt("some_salt")
                    .setCharsetName("UTF8")
                    .setDigestAlgorithm("SHA1")
                    .setBase64Mode(Base64.DEFAULT)
                    .setAlgorithm("AES/CBC/PKCS5Padding")
                    .setSecureRandomAlgorithm("SHA1PRNG")
                    .setSecretKeyType("PBKDF2WithHmacSHA1")
                    .setIv(new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        }

        public Encryption build() {
            try {
                mSecureRandom = SecureRandom.getInstance(mSecureRandomAlgorithm);
                mIvParameterSpec = new IvParameterSpec(mIv);
                return new Encryption(this);
            } catch (NoSuchAlgorithmException e) {
                Log.e(TAG, e.getMessage(), e.getCause());
                return null;
            }
        }

        //region getters and setters

        /**
         * @return the charset name
         */
        public String getCharsetName() {
            return mCharsetName;
        }

        /**
         * @param charsetName the new charset name
         *
         * @return this instance
         */
        public Builder setCharsetName(String charsetName) {
            mCharsetName = charsetName;
            return this;
        }

        /**
         * @return the mAlgorithm used
         */
        public String getAlgorithm() {
            return mAlgorithm;
        }

        /**
         * @param algorithm the mAlgorithm to be used
         *
         * @return this instance
         */
        public Builder setAlgorithm(String algorithm) {
            mAlgorithm = algorithm;
            return this;
        }

        /**
         * @return the Base 64 mode
         */
        public int getBase64Mode() {
            return mBase64Mode;
        }

        /**
         * @param base64Mode set the base 64 mode
         *
         * @return this instance
         */
        public Builder setBase64Mode(int base64Mode) {
            mBase64Mode = base64Mode;
            return this;
        }

        /**
         * @return the type of aes key that will be created, on KITKAT+ the API has changed, if you are getting problems please @see <a href="http://android-developers.blogspot.com.br/2013/12/changes-to-secretkeyfactory-api-in.html">http://android-developers.blogspot.com.br/2013/12/changes-to-secretkeyfactory-api-in.html</a>
         */
        public String getSecretKeyType() {
            return mSecretKeyType;
        }

        /**
         * @param secretKeyType the type of aes key that will be created, on KITKAT+ the API has changed, if you are getting problems please @see <a href="http://android-developers.blogspot.com.br/2013/12/changes-to-secretkeyfactory-api-in.html">http://android-developers.blogspot.com.br/2013/12/changes-to-secretkeyfactory-api-in.html</a>
         *
         * @return this instance
         */
        public Builder setSecretKeyType(String secretKeyType) {
            mSecretKeyType = secretKeyType;
            return this;
        }

        /**
         * @return the value used for salting
         */
        public String getSalt() {
            return mSalt;
        }

        /**
         * @param salt the value used for salting.
         *
         * @return this instance
         */
        public Builder setSalt(String salt) {
            mSalt = salt;
            return this;
        }

        /**
         * @return the length of key
         */
        public int getKeyLength() {
            return mKeyLength;
        }

        /**
         * @param keyLength the length of key
         *
         * @return this instance
         */
        public Builder setKeyLength(int keyLength) {
            mKeyLength = keyLength;
            return this;
        }

        /**
         * @return the number of times the password is hashed
         */
        public int getIterationCount() {
            return mIterationCount;
        }

        /**
         * @param iterationCount the number of times the password is hashed
         *
         * @return this instance
         */
        public Builder setIterationCount(int iterationCount) {
            mIterationCount = iterationCount;
            return this;
        }

        /**
         * @return the algorithm used to generate the secure random
         */
        public String getSecureRandomAlgorithm() {
            return mSecureRandomAlgorithm;
        }

        /**
         * @param secureRandomAlgorithm the algorithm to generate the secure random
         *
         * @return this instance
         */
        public Builder setSecureRandomAlgorithm(String secureRandomAlgorithm) {
            mSecureRandomAlgorithm = secureRandomAlgorithm;
            return this;
        }

        /**
         * @return the IvParameterSpec bytes array
         */
        public byte[] getIv() {
            return mIv;
        }

        /**
         * @param iv the byte array to create a new IvParameterSpec
         *
         * @return this instance
         */
        public Builder setIv(byte[] iv) {
            mIv = iv;
            return this;
        }

        /**
         * @return the SecureRandom
         */
        public SecureRandom getSecureRandom() {
            return mSecureRandom;
        }

        /**
         * @param secureRandom the Secure Random
         *
         * @return this instance
         */
        public Builder setSecureRandom(SecureRandom secureRandom) {
            mSecureRandom = secureRandom;
            return this;
        }

        /**
         * @return the IvParameterSpec
         */
        public IvParameterSpec getIvParameterSpec() {
            return mIvParameterSpec;
        }

        /**
         * @param ivParameterSpec the IvParameterSpec
         *
         * @return this instance
         */
        public Builder setIvParameterSpec(IvParameterSpec ivParameterSpec) {
            mIvParameterSpec = ivParameterSpec;
            return this;
        }

        /**
         * @return the message digest algorithm
         */
        public String getDigestAlgorithm() {
            return mDigestAlgorithm;
        }

        /**
         * @param digestAlgorithm the algorithm to be used to get message digest instance
         *
         * @return this instance
         */
        public Builder setDigestAlgorithm(String digestAlgorithm) {
            mDigestAlgorithm = digestAlgorithm;
            return this;
        }

        //endregion

    }

}
