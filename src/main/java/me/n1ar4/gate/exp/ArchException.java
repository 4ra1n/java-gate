package me.n1ar4.gate.exp;

/**
 * Only support Windows 64 bit
 */
@SuppressWarnings("unused")
public class ArchException extends RuntimeException {
    public ArchException(String msg) {
        super(msg);
    }
}
