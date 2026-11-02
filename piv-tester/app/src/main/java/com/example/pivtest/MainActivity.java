package com.example.pivtest;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Typeface;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbManager;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity implements NfcAdapter.ReaderCallback {
    private static final String ACTION_USB_PERMISSION = "com.example.pivtest.USB_PERMISSION";
    private static final String[] SLOT_NAMES = {
        "9A PIV Authentication", "9C Digital Signature", "9D Key Management", "9E Card Authentication"
    };
    private static final int[] SLOTS = {0x9A, 0x9C, 0x9D, 0x9E};

    private final ExecutorService exec = Executors.newSingleThreadExecutor();
    private volatile Transport transport;
    private TextView status;
    private TextView logView;
    private ScrollView scroll;
    private EditText pinField;
    private EditText apduField;
    private Spinner slotSpinner;
    private NfcAdapter nfc;
    private UsbManager usb;

    private final BroadcastReceiver usbReceiver =
            new BroadcastReceiver() {
                @Override
                public void onReceive(Context ctx, Intent i) {
                    if (!ACTION_USB_PERMISSION.equals(i.getAction())) return;
                    UsbDevice d = Build.VERSION.SDK_INT >= 33
                            ? i.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice.class)
                            : i.getParcelableExtra(UsbManager.EXTRA_DEVICE);
                    if (d != null && i.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
                        openUsb(d);
                    } else {
                        log("USB permission denied");
                    }
                }
            };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        nfc = NfcAdapter.getDefaultAdapter(this);
        usb = (UsbManager) getSystemService(Context.USB_SERVICE);
        buildUi();
        IntentFilter filter = new IntentFilter(ACTION_USB_PERMISSION);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(usbReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(usbReceiver, filter);
        }
        log("NFC: " + (nfc == null ? "not available" : nfc.isEnabled() ? "enabled" : "disabled in settings"));
        setStatus("No card. Tap a card (NFC) or press 'Connect USB reader'.");
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfc != null && nfc.isEnabled()) {
            nfc.enableReaderMode(
                    this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A
                            | NfcAdapter.FLAG_READER_NFC_B
                            | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                    null);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfc != null) nfc.disableReaderMode(this);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unregisterReceiver(usbReceiver);
        closeTransport();
        exec.shutdownNow();
    }

    @Override
    public void onTagDiscovered(final Tag tag) {
        exec.submit(
                new Runnable() {
                    @Override
                    public void run() {
                        IsoDep iso = IsoDep.get(tag);
                        if (iso == null) {
                            log("Tag is not ISO-DEP (14443-4): " + java.util.Arrays.toString(tag.getTechList()));
                            return;
                        }
                        try {
                            closeTransport();
                            NfcTransport t = new NfcTransport(iso);
                            transport = t;
                            byte[] h = t.atrOrHistorical();
                            log("NFC card connected, UID " + Hex.enc(tag.getId())
                                    + (h != null ? ", hist/hilayer " + Hex.enc(h) : ""));
                            setStatus("Connected: NFC");
                            doBasic();
                        } catch (Exception e) {
                            log("NFC connect error: " + e);
                        }
                    }
                });
    }

    private void connectUsb() {
        HashMap<String, UsbDevice> devs = usb.getDeviceList();
        UsbDevice found = null;
        for (UsbDevice d : devs.values()) {
            if (CcidTransport.findInterface(d) != null) {
                found = d;
                break;
            }
        }
        if (found == null) {
            log("No USB CCID reader found (" + devs.size() + " USB device(s) attached). Is OTG enabled?");
            return;
        }
        if (usb.hasPermission(found)) {
            openUsb(found);
        } else {
            log("Requesting USB permission for " + found.getDeviceName());
            usb.requestPermission(
                    found,
                    PendingIntent.getBroadcast(
                            this,
                            0,
                            new Intent(ACTION_USB_PERMISSION).setPackage(getPackageName()),
                            Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0));
        }
    }

    private void openUsb(final UsbDevice d) {
        exec.submit(
                new Runnable() {
                    @Override
                    public void run() {
                        try {
                            closeTransport();
                            UsbDeviceConnection c = usb.openDevice(d);
                            if (c == null) throw new java.io.IOException("openDevice failed");
                            CcidTransport t = new CcidTransport(d, c);
                            transport = t;
                            log("USB reader opened: " + t.name());
                            byte[] atr = t.powerOn();
                            log("ATR: " + Hex.enc(atr));
                            setStatus("Connected: " + t.name());
                            doBasic();
                        } catch (Exception e) {
                            log("USB error: " + e);
                            setStatus("USB failed");
                        }
                    }
                });
    }

    private void closeTransport() {
        Transport t = transport;
        transport = null;
        if (t != null) t.close();
    }

    private Piv piv() {
        Transport t = transport;
        if (t == null) throw new IllegalStateException("No card/reader connected");
        return new Piv(
                t,
                new Piv.Log() {
                    @Override
                    public void log(String s) {
                        MainActivity.this.log(s);
                    }
                });
    }

    private interface Job {
        void run() throws Exception;
    }

    private void async(final String title, final Job job) {
        exec.submit(
                new Runnable() {
                    @Override
                    public void run() {
                        log("== " + title);
                        try {
                            job.run();
                        } catch (Exception e) {
                            log("ERROR: " + e);
                        }
                    }
                });
    }

    private void doBasic() {
        try {
            Piv p = piv();
            Piv.Resp r = p.select();
            log("SELECT PIV: " + r.swHex() + " " + Piv.describeSw(r.sw));
            if (!r.ok()) return;
            Piv.Resp c = p.getData(0x5FC102);
            log("CHUID: " + c.swHex() + " " + Piv.describeSw(c.sw));
            if (c.ok()) {
                byte[] obj = Tlv.find(c.data, 0x53);
                byte[] guid = obj == null ? null : Tlv.find(obj, 0x34);
                if (guid != null) log("  GUID " + Hex.enc(guid));
            }
        } catch (Exception e) {
            log("ERROR: " + e);
        }
    }

    private int selectedSlot() {
        return SLOTS[slotSpinner.getSelectedItemPosition()];
    }

    private String describe(X509Certificate c) {
        return "  subject: " + c.getSubjectDN()
                + "\n  issuer:  " + c.getIssuerDN()
                + "\n  valid:   " + c.getNotBefore() + " .. " + c.getNotAfter()
                + "\n  sigalg:  " + c.getSigAlgName()
                + "\n  key:     " + c.getPublicKey().getAlgorithm()
                + " (PIV alg " + String.format("%02X", Piv.algorithmFor(c.getPublicKey())) + ")";
    }

    private void buildUi() {
        ScrollView root = new ScrollView(this);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (12 * getResources().getDisplayMetrics().density);
        col.setPadding(pad, pad, pad, pad);
        root.addView(col, new ViewGroup.LayoutParams(-1, -2));

        status = new TextView(this);
        status.setTextSize(16);
        status.setTypeface(Typeface.DEFAULT_BOLD);
        col.addView(status);

        col.addView(button("Connect USB reader", new View.OnClickListener() {
            public void onClick(View v) {
                connectUsb();
            }
        }));
        col.addView(button("Select PIV + CHUID", new View.OnClickListener() {
            public void onClick(View v) {
                async("Select PIV + CHUID", new Job() {
                    public void run() {
                        doBasic();
                    }
                });
            }
        }));

        slotSpinner = new Spinner(this);
        slotSpinner.setAdapter(new ArrayAdapter<String>(this, android.R.layout.simple_spinner_dropdown_item, SLOT_NAMES));
        col.addView(slotSpinner);

        col.addView(button("Read certificate (slot)", new View.OnClickListener() {
            public void onClick(View v) {
                final int slot = selectedSlot();
                async("Read cert slot " + Integer.toHexString(slot), new Job() {
                    public void run() throws Exception {
                        Piv p = piv();
                        p.select();
                        log(describe(p.readCert(slot)));
                    }
                });
            }
        }));

        pinField = new EditText(this);
        pinField.setHint("PIN (1-8 chars)");
        pinField.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        col.addView(pinField);

        col.addView(button("PIN retries", new View.OnClickListener() {
            public void onClick(View v) {
                async("PIN retries", new Job() {
                    public void run() throws Exception {
                        Piv p = piv();
                        p.select();
                        Piv.Resp r = p.pinStatus();
                        log(r.ok() ? "PIN already verified" : Piv.describeSw(r.sw));
                    }
                });
            }
        }));
        col.addView(button("Verify PIN", new View.OnClickListener() {
            public void onClick(View v) {
                final String pin = pinField.getText().toString();
                async("Verify PIN", new Job() {
                    public void run() throws Exception {
                        Piv p = piv();
                        p.select();
                        Piv.Resp r = p.verifyPin(pin);
                        log("VERIFY: " + r.swHex() + " " + Piv.describeSw(r.sw));
                    }
                });
            }
        }));
        col.addView(button("Verify PIN + sign test (slot)", new View.OnClickListener() {
            public void onClick(View v) {
                final String pin = pinField.getText().toString();
                final int slot = selectedSlot();
                async("PIN + sign test", new Job() {
                    public void run() throws Exception {
                        Piv p = piv();
                        p.select();
                        Piv.Resp r = p.verifyPin(pin);
                        log("VERIFY: " + r.swHex() + " " + Piv.describeSw(r.sw));
                        if (!r.ok()) return;
                        log(p.signTest(slot));
                    }
                });
            }
        }));

        apduField = new EditText(this);
        apduField.setHint("Raw APDU hex, e.g. 00A4040009A00000030800001000");
        apduField.setTypeface(Typeface.MONOSPACE);
        col.addView(apduField);
        col.addView(button("Send APDU", new View.OnClickListener() {
            public void onClick(View v) {
                final String hex = apduField.getText().toString();
                async("Raw APDU", new Job() {
                    public void run() throws Exception {
                        byte[] a = Hex.dec(hex);
                        if (a.length < 4) throw new IllegalArgumentException("APDU needs at least 4 bytes");
                        Piv.Resp r = piv().raw(a, false);
                        log("SW " + r.swHex() + " " + Piv.describeSw(r.sw));
                    }
                });
            }
        }));
        col.addView(button("Clear log", new View.OnClickListener() {
            public void onClick(View v) {
                logView.setText("");
            }
        }));

        logView = new TextView(this);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextSize(12);
        logView.setTextIsSelectable(true);
        col.addView(logView);
        scroll = root;
        setContentView(root);
    }

    private Button button(String text, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setOnClickListener(l);
        return b;
    }

    private void setStatus(final String s) {
        runOnUiThread(new Runnable() {
            public void run() {
                status.setText(s);
            }
        });
    }

    private void log(final String s) {
        runOnUiThread(new Runnable() {
            public void run() {
                logView.append(s + "\n");
                scroll.post(new Runnable() {
                    public void run() {
                        scroll.fullScroll(View.FOCUS_DOWN);
                    }
                });
            }
        });
    }
}
