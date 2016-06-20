package se.simbio.encryption;

final class Main {

    public static void main(String[] args) {
        Examples examples = new Examples();
        examples.interceptLog();
        examples.normalUsage();
        examples.lowIteration();
        examples.customizedUsage();
        examples.asyncUsage();
    }

}
