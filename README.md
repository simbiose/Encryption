Encryption
=====================

Encryption is a simple way to create encrypted strings to Android project.

[![Android Arsenal](https://img.shields.io/badge/Android%20Arsenal-encryption-brightgreen.svg?style=flat)](https://android-arsenal.com/details/1/935)

#Java Users#

I'm working at new version "1.3.0" and it will works both in Android and Java

#How to use#

1º Add the gradle dependency
```
compile 'se.simbio.encryption:library:1.2.0'
```
2º a) Get an Encryption instance
```
Encryption encryption = Encryption.getDefault("YourKey", "YourSalt", yourByteIvArray);
```
2º b) Or build a new Encryption instance
```
Encryption encryption = new Encryption.Builder()
                .setKeyLength(128)
                .setKey("YourKey")
                .setSalt("YourSalt")
                .setIv(yourByteIvArray)
                .setCharsetName("UTF8")
                .setIterationCount(65536)
                .setDigestAlgorithm("SHA1")
                .setBase64Mode(Base64.DEFAULT)
                .setAlgorithm("AES/CBC/PKCS5Padding")
                .setSecureRandomAlgorithm("SHA1PRNG")
                .setSecretKeyType("PBKDF2WithHmacSHA1")
                .build();
```
3º Encrypt your text
```
String encrypted = encryption.encryptOrNull("Text to be encrypt");
```

4º Decrypt your text
```
String decrypted = encryption.decryptOrNull(encrypted);
```

#FAQ#

 - What is Encryption library?
	 - Encryption library is an Open Source library to help encryption routines in Android applications, our target is to be simple and secure.
 - What is the "IV", what should be my `yourByteIvArray`
	 - Encryption 1.2+ uses by default the AES algorithm in CBC mode, so to encrypt and decrypt works you should have the same key and the same IV byte array to encrypt and to decrypt. An example of IV is `byte[] iv = {-89, -19, 17, -83, 86, 106, -31, 30, -5, -111, 61, -75, -84, 95, 120, -53};` like you can see, 16 bytes in a byte array. So if you want to use this library I recommend you create you own IV and save it :floppy_disk:.
 - I Don't like null returns when errors occurs, what to do to handle errors? 
	 - You have the power to handle the exceptions, instead of uses `encryptOrNull` method just uses the `encrypt` method. The same for the `decryptOrNull`, just uses the `decrypt` method.
 - I'm getting problems with main thread, what to do? 
	 - Encrypt routines can take time, so you can uses the `encryptAsync` with a `Encryption.Callback`to avoid ANR'S. The same for `decryptAsync`
 - I'm an older user, version 1.1 or less, what to do to update Encrypt to version 1.2+?
	 - The library has several changes in his structure in version 1.2, both in algorithm and in code usage, so if you are an older user you need migrate the encrypted stuff or configure the `Builder` manually to the same parameters used in version 1.1 and olds.


##Want to contribute?##

Fell free to contribute, We really like pull requests :octocat:

##License##

GNU Lesser General Public License at version 3


###Third part###

- Copyright (C) 2010 The Android Open Source Project, applied to:
	- Base64 (third.part.android.util.Base64) original comes from [here](https://github.com/android/platform_frameworks_base/blob/ab69e29c1927bdc6143324eba5ccd78f7c43128d/core/java/android/util/Base64.java)
