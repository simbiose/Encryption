package se.simbio.encryption;

import java.security.NoSuchAlgorithmException;

import third.part.android.util.Base64;

/**
 * each method is an example of Encryption
 */
final class Examples {

    void commonUsage() {
        System.out.println("---- Normal Usage ---------------------------------------------------");
        // it is how to get the Encryption instance. You should use your own key your own salt and your own byte array
        Encryption encryption = Encryption.getDefault("SomeKey", "SomeSalt", new byte[16]);

        String secretText = "This is a text to be encrypt, it can be any string that you want";

        // the method encryptOrNull will encrypt your text and if some error occurs will return null
        // if you want handle the errors you can call the encrypt method directly
        String encrypted = encryption.encryptOrNull(secretText);

        // just printing to see the text and the encrypted string
        System.out.println("This is our secret text: " + secretText);
        System.out.println("And this is our encrypted text: " + encrypted);

        // now you can send the encrypted text by network or save in disk securely or do wherever
        // that you want, but remember encrypt is not all, we need decrypt too, so lets go do it
        String decrypted = encryption.decryptOrNull(encrypted);

        // the decrypted text should be equals the encrypted
        System.out.println("And finally this is our decrypted text: " + decrypted);
    }

    void customizedUsage() {
        System.out.println("---- Customized Usage -----------------------------------------------");
        // if you want to change Encryption behavior, maybe to reduce the Iteration Count to get a
        // better performance or also change the Algorithm to a customizable one. You can do this
        // things using your own Encryption.Builder, you can get the default e change few things
        Encryption encryption = null;
        try {
            encryption = Encryption.Builder.getDefaultBuilder("MyKey", "MySalt", new byte[16])
                    .setIterationCount(1) // use 1 instead the default of 65536 << not recommended :) >>
                    .build();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Something wrong: " + e);
        }

        // we also can generate an entire new Builder
        try {
            encryption = new Encryption.Builder()
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
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Something wrong: " + e);
        }

        // now we can use our encryption like we have done in normal usage
        System.out.println("Our encryption instance, can't be null: " + encryption);
    }

    void asyncUsage() {
        System.out.println("---- Async Usage ----------------------------------------------------");
        // the encryption algorithm can take some time and if you cannot lock the thread and wait
        // maybe use an async approach is a good idea, so you can do this like below:
        Encryption encryption = Encryption.getDefault("SomeKey", "SomeSalt", new byte[16]);

        // this method will create a thread and works there, the callback is called when the job is done
        encryption.encryptAsync("This is the text to be encrypt", new Encryption.Callback() {
            @Override
            public void onSuccess(String encrypted) {
                // if no errors occurs you will get your encrypted text here
                System.out.println("My encrypted text: " + encrypted);
            }

            @Override
            public void onError(Exception e) {
                // if an error occurs you will get the exception here
                System.out.println("Oh no! an error has occurred: " + e);
            }
        });

        // if really the job is in background, maybe the print will be show before
        System.out.println("A print from original thread");

        // you can do the same thing to decrypt with decryptAsync
    }

}
