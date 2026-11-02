package com.example.pivtest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.io.ByteArrayInputStream;
import java.util.Arrays;

public class Piv {
    public static final byte[] AID = Hex.dec("A000000308000010000100");

    public static class Resp {
        public final byte[] data;
        public final int sw;

        Resp(byte[] data, int sw) {
            this.data = data;
            this.sw = sw;
        }

        public boolean ok() {
            return sw == 0x9000;
        }

        public String swHex() {
            return String.format("%04X", sw);
        }
    }

    public interface Log {
        void log(String s);
    }

    private final Transport t;
    private final Log log;

    public Piv(Transport t, Log log) {
        this.t = t;
        this.log = log;
    }

    /** Sends a raw APDU and handles 61xx / 6Cxx. Logs both directions. */
    public Resp raw(byte[] apdu, boolean maskLog) throws IOException {
        log.log("> " + (maskLog ? Hex.enc(apdu, 0, Math.min(5, apdu.length)) + "...(masked)" : Hex.enc(apdu)));
        byte[] r = t.transmit(apdu);
        ByteArrayOutputStream acc = new ByteArrayOutputStream();
        while (true) {
            if (r.length < 2) throw new IOException("response too short: " + Hex.enc(r));
            int sw = ((r[r.length - 2] & 0xff) << 8) | (r[r.length - 1] & 0xff);
            acc.write(r, 0, r.length - 2);
            int sw1 = sw >> 8;
            if (sw1 == 0x61) {
                r = t.transmit(new byte[] {0x00, (byte) 0xC0, 0, 0, (byte) (sw & 0xff)});
                continue;
            }
            if (sw1 == 0x6C && apdu.length == 5) {
                byte[] a = Arrays.copyOf(apdu, 5);
                a[4] = (byte) (sw & 0xff);
                r = t.transmit(a);
                acc.reset();
                continue;
            }
            byte[] data = acc.toByteArray();
            log.log("< " + (data.length > 0 ? Hex.enc(data) + " " : "") + String.format("%04X", sw));
            return new Resp(data, sw);
        }
    }

    public Resp send(int cla, int ins, int p1, int p2, byte[] data, boolean mask) throws IOException {
        if (data == null) data = new byte[0];
        int off = 0;
        while (data.length - off > 255) {
            byte[] chunk = Arrays.copyOfRange(data, off, off + 255);
            Resp r = raw(apdu(cla | 0x10, ins, p1, p2, chunk, false), mask);
            if (!r.ok()) return r;
            off += 255;
        }
        return raw(apdu(cla, ins, p1, p2, Arrays.copyOfRange(data, off, data.length), ins != 0x20), mask);
    }

    private static byte[] apdu(int cla, int ins, int p1, int p2, byte[] data, boolean le) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(cla);
        o.write(ins);
        o.write(p1);
        o.write(p2);
        if (data.length > 0) {
            o.write(data.length);
            o.write(data, 0, data.length);
        }
        if (le) o.write(0);
        return o.toByteArray();
    }

    public Resp select() throws IOException {
        return send(0x00, 0xA4, 0x04, 0x00, AID, false);
    }

    public Resp getData(int tag) throws IOException {
        byte[] obj = new byte[] {0x5C, 0x03, (byte) (tag >> 16), (byte) (tag >> 8), (byte) tag};
        return send(0x00, 0xCB, 0x3F, 0xFF, obj, false);
    }

    public Resp verifyPin(String pin) throws IOException {
        byte[] p = new byte[8];
        Arrays.fill(p, (byte) 0xFF);
        byte[] b = pin.getBytes("US-ASCII");
        if (b.length < 1 || b.length > 8) throw new IOException("PIN must be 1-8 chars");
        System.arraycopy(b, 0, p, 0, b.length);
        try {
            return send(0x00, 0x20, 0x00, 0x80, p, true);
        } finally {
            Arrays.fill(p, (byte) 0);
        }
    }

    public Resp pinStatus() throws IOException {
        return send(0x00, 0x20, 0x00, 0x80, null, false);
    }

    public static String describeSw(int sw) {
        if (sw == 0x9000) return "OK";
        if ((sw & 0xFFF0) == 0x63C0) return "wrong PIN, " + (sw & 0xF) + " retries left";
        switch (sw) {
            case 0x6982: return "security status not satisfied (PIN needed)";
            case 0x6983: return "PIN blocked";
            case 0x6A82: return "file/object not found";
            case 0x6A80: return "incorrect data";
            case 0x6A86: return "incorrect P1/P2 (e.g. unsupported key/algorithm)";
            case 0x6D00: return "INS not supported";
            case 0x6E00: return "CLA not supported";
            case 0x6700: return "wrong length";
            case 0x6985: return "conditions not satisfied";
            default: return "unexpected status";
        }
    }

    public static int certTag(int slot) {
        switch (slot) {
            case 0x9A: return 0x5FC105;
            case 0x9C: return 0x5FC10A;
            case 0x9D: return 0x5FC10B;
            case 0x9E: return 0x5FC101;
            default: throw new IllegalArgumentException("unsupported slot");
        }
    }

    public X509Certificate readCert(int slot) throws Exception {
        Resp r = getData(certTag(slot));
        if (!r.ok()) throw new IOException("GET DATA failed: " + r.swHex() + " " + describeSw(r.sw));
        byte[] obj = Tlv.find(r.data, 0x53);
        byte[] der = obj == null ? null : Tlv.find(obj, 0x70);
        if (der == null) throw new IOException("no certificate in object");
        if (obj != null) {
            byte[] info = Tlv.find(obj, 0x71);
            if (info != null && info.length > 0 && (info[0] & 0x01) != 0) {
                java.util.zip.GZIPInputStream gz =
                        new java.util.zip.GZIPInputStream(new ByteArrayInputStream(der));
                ByteArrayOutputStream o = new ByteArrayOutputStream();
                byte[] buf = new byte[1024];
                int n;
                while ((n = gz.read(buf)) > 0) o.write(buf, 0, n);
                der = o.toByteArray();
            }
        }
        return (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    /** PIV algorithm id for a public key, or -1. */
    public static int algorithmFor(PublicKey k) {
        if (k instanceof RSAPublicKey) {
            int bits = ((RSAPublicKey) k).getModulus().bitLength();
            if (bits > 1024) return 0x07;
            return 0x06;
        }
        if (k instanceof ECPublicKey) {
            int bits = ((ECPublicKey) k).getParams().getOrder().bitLength();
            if (bits == 256) return 0x11;
            if (bits == 384) return 0x14;
        }
        return -1;
    }

    private static final byte[] SHA256_PREFIX =
            Hex.dec("3031300d060960864801650304020105000420");

    /** Signs a random challenge with the key in the given slot (PIN must already be verified) and verifies it. */
    public String signTest(int slot) throws Exception {
        X509Certificate cert = readCert(slot);
        PublicKey pub = cert.getPublicKey();
        int alg = algorithmFor(pub);
        if (alg < 0) throw new IOException("unsupported key type " + pub.getAlgorithm());

        byte[] challenge = new byte[32];
        new java.security.SecureRandom().nextBytes(challenge);
        byte[] input;
        String jca;
        if (alg == 0x06 || alg == 0x07) {
            int size = alg == 0x07 ? 256 : 128;
            byte[] h = MessageDigest.getInstance("SHA-256").digest(challenge);
            input = new byte[size];
            Arrays.fill(input, (byte) 0xFF);
            input[0] = 0x00;
            input[1] = 0x01;
            int tail = SHA256_PREFIX.length + h.length;
            input[size - tail - 1] = 0x00;
            System.arraycopy(SHA256_PREFIX, 0, input, size - tail, SHA256_PREFIX.length);
            System.arraycopy(h, 0, input, size - h.length, h.length);
            jca = "SHA256withRSA";
        } else if (alg == 0x11) {
            input = MessageDigest.getInstance("SHA-256").digest(challenge);
            jca = "SHA256withECDSA";
        } else {
            input = MessageDigest.getInstance("SHA-384").digest(challenge);
            jca = "SHA384withECDSA";
        }

        byte[] body = Tlv.build(0x82, new byte[0]);
        byte[] chal = Tlv.build(0x81, input);
        byte[] req = new byte[body.length + chal.length];
        System.arraycopy(body, 0, req, 0, body.length);
        System.arraycopy(chal, 0, req, body.length, chal.length);
        Resp r = send(0x00, 0x87, alg, slot, Tlv.build(0x7C, req), false);
        if (!r.ok()) throw new IOException("GENERAL AUTHENTICATE failed: " + r.swHex() + " " + describeSw(r.sw));
        byte[] tmpl = Tlv.find(r.data, 0x7C);
        byte[] sig = tmpl == null ? null : Tlv.find(tmpl, 0x82);
        if (sig == null) throw new IOException("no signature in response");

        Signature s = Signature.getInstance(jca);
        s.initVerify(pub);
        s.update(challenge);
        boolean valid = s.verify(sig);
        return String.format(
                "slot %02X alg %02X (%s): signature %s (%d bytes)",
                slot, alg, jca, valid ? "VALID" : "INVALID", sig.length);
    }
}
