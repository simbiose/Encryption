package se.simbio.encryption

import java.security.NoSuchAlgorithmException

import third.part.android.util.Base64

/**
 * each method is an example of Encryption
 */

fun commonUsage() {
    println("---- Normal Usage ---------------------------------------------------")
    // it is how to get the Encryption instance. You should use your own key your own salt and your own byte array
    val encryption = Encryption.getDefault("SomeKey", "SomeSalt", ByteArray(16))

    val secretText = "This is a text to be encrypt, it can be any string that you want"

    // the method encryptOrNull will encrypt your text and if some error occurs will return null
    // if you want handle the errors you can call the encrypt method directly
    val encrypted = encryption.encryptOrNull(secretText)

    // just printing to see the text and the encrypted string
    println("This is our secret text: " + secretText)
    println("And this is our encrypted text: " + encrypted)

    // now you can send the encrypted text by network or save in disk securely or do wherever
    // that you want, but remember encrypt is not all, we need decrypt too, so lets go do it
    val decrypted = encryption.decryptOrNull(encrypted)

    // the decrypted text should be equals the encrypted
    println("And finally this is our decrypted text: " + decrypted)
}

fun customizedUsage() {
    println("---- Customized Usage -----------------------------------------------")
    // if you want to change Encryption behavior, maybe to reduce the Iteration Count to get a
    // better performance or also change the Algorithm to a customizable one. You can do this
    // things using your own Encryption.Builder, you can get the default e change few things
    var encryption: Encryption? = null
    try {
        encryption = Encryption.Builder.getDefaultBuilder("MyKey", "MySalt", ByteArray(16)).setIterationCount(1).build()
    } catch (e: NoSuchAlgorithmException) {
        println("Something wrong: " + e)
    }

    // we also can generate an entire new Builder
    try {
        encryption = Encryption.Builder().setKeyLength(128).setKeyAlgorithm("AES").setCharsetName("UTF8").setIterationCount(65536).setKey("mor€Z€cr€tKYss").setDigestAlgorithm("SHA1").setSalt("A beautiful salt").setBase64Mode(Base64.DEFAULT).setAlgorithm("AES/CBC/PKCS5Padding").setSecureRandomAlgorithm("SHA1PRNG").setSecretKeyType("PBKDF2WithHmacSHA1").setIv(byteArrayOf(29, 88, -79, -101, -108, -38, -126, 90, 52, 101, -35, 114, 12, -48, -66, -30)).build()
    } catch (e: NoSuchAlgorithmException) {
        println("Something wrong: " + e)
    }

    // now we can use our encryption like we have done in normal usage
    println("Our encryption instance, can't be null: " + encryption!!)
}

fun asyncUsage() {
    println("---- Async Usage ----------------------------------------------------")
    // the encryption algorithm can take some time and if you cannot lock the thread and wait
    // maybe use an async approach is a good idea, so you can do this like below:
    val encryption = Encryption.getDefault("SomeKey", "SomeSalt", ByteArray(16))

    // this method will create a thread and works there, the callback is called when the job is done
    encryption.encryptAsync("This is the text to be encrypt", object : Encryption.Callback {
        override fun onSuccess(encrypted: String) {
            // if no errors occurs you will get your encrypted text here
            println("My encrypted text: " + encrypted)
        }

        override fun onError(e: Exception) {
            // if an error occurs you will get the exception here
            println("Oh no! an error has occurred: " + e)
        }
    })

    // if really the job is in background, maybe the print will be show before
    println("A print from original thread")

    // you can do the same thing to decrypt with decryptAsync
}
