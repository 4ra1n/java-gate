package me.n1ar4.gate.exp;

/**
 * Shellcode must be not null
 */
@SuppressWarnings("unused")
public class ShellCodeException extends RuntimeException {
    public ShellCodeException(String msg) {
        super(msg);
    }
}
