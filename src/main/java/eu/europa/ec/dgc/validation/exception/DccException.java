package eu.europa.ec.dgc.validation.exception;

public class DccException extends RuntimeException {
    public int getStatus() {
        return status;
    }

    private int status = 500;

    public DccException(String message, Throwable inner) {
        super(message, inner);
    }

    public DccException(String message) {
        super(message);
    }

    public DccException(String message, Throwable inner, int status) {
        super(message, inner);
        this.status = status;
    }

    public DccException(String message, int status) {
        super(message);
        this.status = status;
    }



}
