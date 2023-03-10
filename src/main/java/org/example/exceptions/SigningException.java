package org.example.exceptions;

public class SigningException extends Exception {
    public SigningException(String errorMessage, Throwable err) {
        super(errorMessage, err);
    }
}
