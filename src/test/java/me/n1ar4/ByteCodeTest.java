package me.n1ar4;

import me.n1ar4.gate.util.ByteUtil;

public class ByteCodeTest {
    public static void main(String[] args) {
        byte[] code = ByteUtil.hexStringToByteArray("aa01bb02cc03dd04");
        if (code.length == 8 && code[3] == 2) {
            System.out.println("test success");
        }
    }
}
