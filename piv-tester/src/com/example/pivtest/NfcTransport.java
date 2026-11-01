package com.example.pivtest;

import android.nfc.tech.IsoDep;
import java.io.IOException;

public class NfcTransport implements Transport {
    private final IsoDep iso;

    public NfcTransport(IsoDep iso) throws IOException {
        this.iso = iso;
        iso.connect();
        iso.setTimeout(10000);
    }

    @Override
    public byte[] transmit(byte[] apdu) throws IOException {
        return iso.transceive(apdu);
    }

    public byte[] atrOrHistorical() {
        byte[] h = iso.getHistoricalBytes();
        if (h != null) return h;
        return iso.getHiLayerResponse();
    }

    @Override
    public String name() {
        return "NFC IsoDep";
    }

    @Override
    public void close() {
        try {
            iso.close();
        } catch (IOException ignored) {
        }
    }
}
