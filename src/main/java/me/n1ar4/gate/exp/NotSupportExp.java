package me.n1ar4.gate.exp;

/**
 * Only support Windows 64 bit
 */
@SuppressWarnings("unused")
public class NotSupportExp extends RuntimeException {
    public NotSupportExp(String msg) {
        super(msg);
    }
}
