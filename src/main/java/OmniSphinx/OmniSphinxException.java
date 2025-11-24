package OmniSphinx;


public class OmniSphinxException extends Exception {

    public OmniSphinxException(String message) {
        super(message);
    }

    public OmniSphinxException(String message, Throwable cause) {
        super(message, cause);
    }

    public OmniSphinxException(Throwable cause) {
        super(cause);
    }
}