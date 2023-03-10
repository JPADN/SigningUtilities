package org.example.exceptions;

public class SignatureVerificationException extends Exception {
    public SignatureVerificationException(String errorMessage, Throwable err) {
        super(errorMessage, err);
    }
}
