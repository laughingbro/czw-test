package com.example.pivtest;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public final class Tlv {
    private Tlv() {}

    /** Returns the value of the first top-level TLV with the given tag, or null. */
    public static byte[] find(byte[] d, int wantTag) {
        int i = 0;
        while (i < d.length) {
            int tag = d[i++] & 0xff;
            if ((tag & 0x1f) == 0x1f) {
                int b;
                do {
                    if (i >= d.length) return null;
                    b = d[i++] & 0xff;
                    tag = (tag << 8) | b;
                } while ((b & 0x80) != 0);
            }
            if (i >= d.length) return null;
            int len = d[i++] & 0xff;
            if (len >= 0x80) {
                int n = len & 0x7f;
                len = 0;
                for (int k = 0; k < n; k++) {
                    if (i >= d.length) return null;
                    len = (len << 8) | (d[i++] & 0xff);
                }
            }
            if (len < 0 || i + len > d.length) return null;
            if (tag == wantTag) return Arrays.copyOfRange(d, i, i + len);
            i += len;
        }
        return null;
    }

    public static byte[] build(int tag, byte[] value) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if (tag > 0xff) o.write(tag >> 8);
        o.write(tag & 0xff);
        int l = value.length;
        if (l < 0x80) {
            o.write(l);
        } else if (l < 0x100) {
            o.write(0x81);
            o.write(l);
        } else {
            o.write(0x82);
            o.write(l >> 8);
            o.write(l & 0xff);
        }
        o.write(value, 0, value.length);
        return o.toByteArray();
    }
}
