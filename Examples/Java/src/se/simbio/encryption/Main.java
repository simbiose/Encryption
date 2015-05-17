package se.simbio.encryption;

public class Main {

    public static void main(String[] args) {
        Examples examples = new Examples();
        examples.interceptLog();
        examples.normalUsage();
        examples.customizedUsage();
        examples.asyncUsage();
    }

}
