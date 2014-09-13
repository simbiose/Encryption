Encryption
=====================

Encryption is a simple way to create encrypted strings to Android project.

[![Android Arsenal](https://img.shields.io/badge/Android%20Arsenal-encryption-brightgreen.svg?style=flat)](https://android-arsenal.com/details/1/935)

#How to use#
1º Add the gradle dependencie
```
compile 'se.simbio.encryption:library:1.0.0'
```
2º Use it
```
String key = "$3creTQei";
String secretText = "Text to be encrypt";
Encryption encryption = new Encryption();
String encrypted = encryption.encrypt(key, secretText);
String decrypted = encryption.decrypt(key, encrypted);
Log.d("Encryption", String.format("The text '%s' encrypted with key '%s' is %s", secretText, key, encrypted));
Log.d("Encryption", String.format("This is the text '%s' decrypted with key '%s' on %s", decrypted, key, encrypted));
```

##License##
GNU Lesser General Public License at version 3

##Developed By##
* Simbio.se <http://simbio.se/>
* Ademar Oliveira - <ademar111190@gmail.com>

