package com.example.pivtest;

import java.io.IOException;

public interface Transport {
    byte[] transmit(byte[] apdu) throws IOException;

    String name();

    void close();
}
