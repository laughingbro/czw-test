package com.example.pivtest;

public final class Hex {
    private Hex() {}

    public static String enc(byte[] b) {
        return enc(b, 0, b.length);
    }

    public static String enc(byte[] b, int off, int len) {
        StringBuilder sb = new StringBuilder();
        for (int i = off; i < off + len; i++) {
            sb.append(String.format("%02X", b[i] & 0xff));
        }
        return sb.toString();
    }

    public static byte[] dec(String s) {
        s = s.replaceAll("[^0-9A-Fa-f]", "");
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("odd number of hex digits");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}
