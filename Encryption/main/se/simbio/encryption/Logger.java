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

/**
 * A class to log. you can change the delegate @class(EncryptionLogDelegate) and uses your own log
 */
public class Logger {

    /**
     * The delegate to log
     */
    private static EncryptionLogDelegate sLogDelegate = new DefaultEncryptionLogDelegate();

    /**
     * A method to log exceptions
     *
     * @param message   the message
     * @param exception the @class(Exception)
     */
    public static void log(String message, Exception exception) {
        sLogDelegate.log(message, exception);
    }

    /**
     * A method to log
     *
     * @param message the message
     */
    public static void log(String message) {
        sLogDelegate.log(message);
    }

    /**
     * You can use a custom @class(EncryptionLogDelegate) to get Encryption messages
     *
     * @param logDelegate the @class(EncryptionLogDelegate) to get logs
     */
    public static void setLogDelegate(EncryptionLogDelegate logDelegate) {
        sLogDelegate = logDelegate != null ? logDelegate : new DefaultEncryptionLogDelegate();
    }

    /**
     * Send the logs to System.out
     */
    public static void enableDefaultLog() {
        setLogDelegate(new SystemOutEncryptionLogDelegate());
    }

    /**
     * Don't log
     */
    public static void disableLog() {
        setLogDelegate(new DefaultEncryptionLogDelegate());
    }

    /**
     * The interface to implements on your log delegate
     */
    public interface EncryptionLogDelegate {

        /**
         * The log exceptions from Encryption
         *
         * @param message   the message
         * @param exception the @class(Exception)
         */
        void log(String message, Exception exception);

        /**
         * The log message from Encryption
         *
         * @param message the message
         */
        void log(String message);

    }

    /**
     * A default log delegate that do nothing
     */
    public static class DefaultEncryptionLogDelegate implements EncryptionLogDelegate {

        @Override
        public void log(String message, Exception exception) {}

        @Override
        public void log(String message) {}

    }

    /**
     * A log delegate to System.out
     */
    public static class SystemOutEncryptionLogDelegate implements EncryptionLogDelegate {

        @Override
        public void log(String message, Exception exception) {
            System.out.println(String.format("%s : %s", message, exception));
        }

        @Override
        public void log(String message) {
            System.out.println(message);
        }

    }

}
