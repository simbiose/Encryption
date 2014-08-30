Encryption
=====================

Encryption is a simple way to create encrypted strings to Android project.

#How to use#
1. Add the gradle dependencie
```
TODO maven repository
```
2. Use it
```
Encryption encryption = new Encryption();
String textToEncrypt = "Top Secret Text";
String encryptKey = "Key";
String encryptedText = encryption.encrypt(encryptKey, textToEncrypt);
String decryptedText = encryption.decrypt(encryptKey, encryptedText);
```

##License##
GNU General Public License at version 3, more details at [LICENSE](https://github.com/simbiose/Encryption/blob/master/LICENSE)

##Developed By##
* Simbio.se <http://simbio.se/>
* Ademar Oliveira - <ademar111190@gmail.com>

