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
import android.os.Build;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A class to make more easy simple encrypt routines
 */
public class Encryption {

    private static final String TAG = "Encryption";

    //char set
    private String mCharsetName = "UTF8";
    //base mode
    private int mBase64Mode = Base64.DEFAULT;
    //type of aes key that will be created, on KITKAT+ the API has changed, if you are getting problems please @see <a href="http://android-developers.blogspot.com.br/2013/12/changes-to-secretkeyfactory-api-in.html">http://android-developers.blogspot.com.br/2013/12/changes-to-secretkeyfactory-api-in.html</a>
    private String mSecretKeyType = "PBKDF2WithHmacSHA1";
    //value used for salting. can be anything
    private String mSalt = "some_salt";
    //length of key
    private int mKeyLength = 128;
    //number of times the password is hashed
    private int mIterationCount = 65536;
    //main family of aes
    private String mAlgorithm = "AES";

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
            byte[] dataBytes = data.getBytes(mCharsetName);
            Cipher cipher = Cipher.getInstance(mAlgorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.encodeToString(cipher.doFinal(dataBytes), mBase64Mode);
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
            byte[] dataBytes = Base64.decode(data, mBase64Mode);
            SecretKey secretKey = getSecretKey(hashTheKey(key));
            Cipher cipher = Cipher.getInstance(mAlgorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
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
        SecretKeyFactory factory;
        factory = SecretKeyFactory.getInstance(mSecretKeyType);

        KeySpec spec = new PBEKeySpec(key,
                mSalt.getBytes(mCharsetName),
                mIterationCount,
                mKeyLength);

        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), mAlgorithm);
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
        MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(key.getBytes(mCharsetName));
        return Base64.encodeToString(md.digest(), Base64.NO_PADDING).toCharArray();
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
     */
    public void setCharsetName(String charsetName) {
        mCharsetName = charsetName;
    }

    /**
     * @return the mAlgorithm used
     */
    public String getAlgorithm() {
        return mAlgorithm;
    }

    /**
     * @param algorithm the mAlgorithm to be used
     */
    public void setAlgorithm(String algorithm) {
        mAlgorithm = algorithm;
    }

    /**
     * @return the Base 64 mode
     */
    public int getBase64Mode() {
        return mBase64Mode;
    }

    /**
     * @param base64Mode set the base 64 mode
     */
    public void setBase64Mode(int base64Mode) {
        mBase64Mode = base64Mode;
    }

    /**
     * @return the type of aes key that will be created
     */
    public String getSecretKeyType() {
        return mSecretKeyType;
    }

    /**
     * @param secretKeyType the type of aes key that will be created//
     */
    public void setSecretKeyType(String secretKeyType) {
        mSecretKeyType = secretKeyType;
    }

    /**
     * @return the value used for salting
     */
    public String getSalt() {
        return mSalt;
    }

    /**
     * @param salt the value used for salting.
     */
    public void setSalt(String salt) {
        mSalt = salt;
    }

    /**
     * @return the length of key
     */
    public int getKeyLength() {
        return mKeyLength;
    }

    /**
     * @param keyLength the length of key
     */
    public void setKeyLength(int keyLength) {
        mKeyLength = keyLength;
    }

    /**
     * @return the number of times the password is hashed
     */
    public int getIterationCount() {
        return mIterationCount;
    }

    /**
     * @param iterationCount the number of times the password is hashed
     */
    public void setIterationCount(int iterationCount) {
        mIterationCount = iterationCount;
    }

    //endregion

}
