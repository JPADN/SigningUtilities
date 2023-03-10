package org.example.exceptions;

public class EtapaDesafioException extends Exception {
    public EtapaDesafioException(String errorMessage, Throwable err) {
        super(errorMessage, err);
    }
}
