package javasphinx;

/**
 * Custom RuntimeException type raised during irrecoverable issues
 */
public class SphinxException extends Exception {
    public SphinxException(String message) {
        super(message);
    }
}