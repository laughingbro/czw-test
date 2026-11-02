package com.example.pivtest;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/** Minimal USB CCID transport (short/extended APDU level readers). */
public class CcidTransport implements Transport {
    public static final int CLASS_SMART_CARD = 0x0B;
    private static final int TIMEOUT = 8000;

    private final UsbDevice device;
    private final UsbDeviceConnection conn;
    private final UsbInterface iface;
    private final UsbEndpoint in;
    private final UsbEndpoint out;
    private int seq = 0;
    private byte[] atr = new byte[0];

    public static UsbInterface findInterface(UsbDevice d) {
        for (int i = 0; i < d.getInterfaceCount(); i++) {
            UsbInterface f = d.getInterface(i);
            if (f.getInterfaceClass() == CLASS_SMART_CARD) return f;
        }
        return null;
    }

    public CcidTransport(UsbDevice device, UsbDeviceConnection conn) throws IOException {
        this.device = device;
        this.conn = conn;
        this.iface = findInterface(device);
        if (iface == null) throw new IOException("no CCID interface");
        UsbEndpoint i = null, o = null;
        for (int k = 0; k < iface.getEndpointCount(); k++) {
            UsbEndpoint e = iface.getEndpoint(k);
            if (e.getType() != UsbConstants.USB_ENDPOINT_XFER_BULK) continue;
            if (e.getDirection() == UsbConstants.USB_DIR_IN) i = e;
            else o = e;
        }
        if (i == null || o == null) throw new IOException("bulk endpoints not found");
        in = i;
        out = o;
        if (!conn.claimInterface(iface, true)) throw new IOException("claimInterface failed");
    }

    public byte[] powerOn() throws IOException {
        // bPowerSelect = 0 (automatic voltage)
        atr = exchange(0x62, new byte[0], new byte[] {0, 0, 0});
        return atr;
    }

    public byte[] getAtr() {
        return atr;
    }

    private byte[] exchange(int type, byte[] data, byte[] specific) throws IOException {
        int mySeq = seq++ & 0xff;
        byte[] msg = new byte[10 + data.length];
        msg[0] = (byte) type;
        msg[1] = (byte) data.length;
        msg[2] = (byte) (data.length >> 8);
        msg[3] = (byte) (data.length >> 16);
        msg[4] = (byte) (data.length >> 24);
        msg[5] = 0; // slot
        msg[6] = (byte) mySeq;
        System.arraycopy(specific, 0, msg, 7, 3);
        System.arraycopy(data, 0, msg, 10, data.length);

        int pkt = Math.max(out.getMaxPacketSize(), 64);
        for (int off = 0; off < msg.length; off += pkt) {
            int n = Math.min(pkt, msg.length - off);
            byte[] chunk = Arrays.copyOfRange(msg, off, off + n);
            int r = conn.bulkTransfer(out, chunk, n, TIMEOUT);
            if (r != n) throw new IOException("bulk OUT failed: " + r);
        }
        if (msg.length % pkt == 0) {
            conn.bulkTransfer(out, new byte[0], 0, TIMEOUT);
        }

        while (true) {
            byte[] resp = readMessage();
            if ((resp[6] & 0xff) != mySeq) continue;
            int status = resp[7] & 0xff;
            int cmdStatus = (status >> 6) & 3;
            int iccStatus = status & 3;
            if (cmdStatus == 2) continue; // time extension, wait for the real response
            if (cmdStatus == 1) {
                throw new IOException(
                        iccStatus == 2
                                ? "no card present in reader"
                                : String.format("CCID error 0x%02X (icc status %d)", resp[8] & 0xff, iccStatus));
            }
            int len = (resp[1] & 0xff) | ((resp[2] & 0xff) << 8) | ((resp[3] & 0xff) << 16);
            return Arrays.copyOfRange(resp, 10, 10 + len);
        }
    }

    private byte[] readMessage() throws IOException {
        int bufSize = Math.max(in.getMaxPacketSize(), 64);
        ByteArrayOutputStream acc = new ByteArrayOutputStream();
        byte[] buf = new byte[bufSize];
        int expected = -1;
        while (true) {
            int r = conn.bulkTransfer(in, buf, buf.length, TIMEOUT);
            if (r < 0) throw new IOException("bulk IN failed (timeout?)");
            acc.write(buf, 0, r);
            byte[] cur = acc.toByteArray();
            if (expected < 0 && cur.length >= 10) {
                int len = (cur[1] & 0xff) | ((cur[2] & 0xff) << 8) | ((cur[3] & 0xff) << 16);
                expected = 10 + len;
            }
            if (expected >= 0 && cur.length >= expected) return cur;
            if (r == 0) throw new IOException("short CCID message");
        }
    }

    @Override
    public byte[] transmit(byte[] apdu) throws IOException {
        // bBWI = 0, wLevelParameter = 0
        return exchange(0x6F, apdu, new byte[] {0, 0, 0});
    }

    @Override
    public String name() {
        return "USB CCID (" + device.getProductName() + ")";
    }

    @Override
    public void close() {
        try {
            conn.releaseInterface(iface);
        } catch (Exception ignored) {
        }
        conn.close();
    }
}
