Encryption
=====================

Encryption is a simple way to encrypt and decrypt strings on Android and Java project.

[![](https://jitpack.io/v/simbiose/Encryption.svg)](https://jitpack.io/#simbiose/Encryption) [![Android Arsenal](https://img.shields.io/badge/Android%20Arsenal-encryption-brightgreen.svg?style=flat)](https://android-arsenal.com/details/1/935) [![Build Status](https://www.bitrise.io/app/fc607e87ae734d03/status.svg?token=dtlsgmtrxOrDdVqdtaxK-g&branch=master)](https://www.bitrise.io/app/fc607e87ae734d03) [![Build Status](https://semaphoreci.com/api/v1/projects/f74e04e6-bd08-4faa-ba77-a5ee51d0f82e/680132/badge.svg)](https://semaphoreci.com/ademar111190/encryption)

## How to use ##

1º Add [JitPack](https://jitpack.io/) to your build file
```
allprojects {
  repositories {
    ...
    maven { url 'https://jitpack.io' }
  }
}
```

2º Add the gradle dependency
```
compile 'com.github.simbiose:Encryption:2.0.1'
```

3º Get an Encryption instance
```
String key = "YourKey";
String salt = "YourSalt";
byte[] iv = new byte[16];
Encryption encryption = Encryption.getDefault(key, salt, iv);
```

4º Encrypt your text
```
String encrypted = encryption.encryptOrNull("Text to be encrypt");
```

5º Decrypt your text
```
String decrypted = encryption.decryptOrNull(encrypted);
```

## Custom usage ##

You can use you own builder
```
Encryption encryption = new Encryption.Builder()
                .setKeyLength(128)
                .setKey("YourKey")
                .setSalt("YourSalt")
                .setIv(yourByteIvArray)
                .setCharsetName("UTF8")
                .setIterationCount(1)
                .setDigestAlgorithm("SHA1")
                .setBase64Mode(Base64.DEFAULT)
                .setAlgorithm("AES/CBC/PKCS5Padding")
                .setSecureRandomAlgorithm("SHA1PRNG")
                .setSecretKeyType("PBKDF2WithHmacSHA1")
                .build();
```

See more on Examples folder, there is an Android, a Java and a Kotlin project.

## FAQ ##

 - What is Encryption library?
	 - Encryption library is an Open Source library to help encryption routines in Android and Java applications, our target is to be simple and secure.
 - What is the "IV", what should be my `yourByteIvArray`
	 - Encryption 1.2+ uses by default the AES algorithm in CBC mode, so to encrypt and decrypt works you should have the same key and the same IV byte array to encrypt and to decrypt. An example of IV is `byte[] iv = {-89, -19, 17, -83, 86, 106, -31, 30, -5, -111, 61, -75, -84, 95, 120, -53};` like you can see, 16 bytes in a byte array. So if you want to use this library I recommend you create you own IV and save it :floppy_disk:.
 - I Don't like null returns when errors occurs, what to do to handle errors?
	 - You have the power to handle the exceptions, instead of uses `encryptOrNull` method just uses the `encrypt` method. The same for the `decryptOrNull`, just uses the `decrypt` method.
 - I'm getting problems with main thread, what to do?
	 - Encrypt routines can take time, so you can uses the `encryptAsync` with a `Encryption.Callback`to avoid ANR'S. The same for `decryptAsync`
 - I'm an older user, version 1.4 or less, what to do to update Encrypt to version 2.+?
     - The library has changed the default iteration count from 65536 to 1, it improve the performance, if you have a code using the old version or if you prefer to use a big iteration count you just need to use a custom builder instead of get the default builder and set the iteration count you want
     - As far as the library uses 1 as default iteration count we do not need anymore the getLowIteration and it was removed from project, if you use it you can just change to getDefault
     - MIT is the project license so feel free to use it :tada:
 - I'm a very older user, version 1.1 or less, what to do to update Encrypt to version 1.2+?
	 - The library has several changes in his structure in version 1.2, both in algorithm and in code usage, so if you are an older user you need migrate the encrypted stuff or configure the `Builder` manually to the same parameters used in version 1.1 and olds.


### Want to contribute? ###

Fell free to contribute, We really like pull requests :octocat:


#### Third part ####

- Copyright (C) 2010 The Android Open Source Project, applied to:
	- Base64 (third.part.android.util.Base64) original comes from [here](https://github.com/android/platform_frameworks_base/blob/ab69e29c1927bdc6143324eba5ccd78f7c43128d/core/java/android/util/Base64.java)
