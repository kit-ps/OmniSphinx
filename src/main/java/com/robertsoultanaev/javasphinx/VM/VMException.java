package com.robertsoultanaev.javasphinx.VM;

public class VMException extends Exception {
    public VMException(String message) {
        super(message);
    }

    public VMException(String message, Throwable cause) {
        super(message, cause);
    }
}