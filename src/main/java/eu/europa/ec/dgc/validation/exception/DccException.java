package eu.europa.ec.dgc.validation.exception;

public class DccException extends RuntimeException {
    public DccException(String message, Throwable inner) {
        super(message, inner);
    }

    public DccException(String message) {
        super(message);
    }
}
