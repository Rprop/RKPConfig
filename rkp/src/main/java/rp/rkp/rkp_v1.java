package rp.rkp;

import android.os.Build;
import android.os.IBinder;
import android.os.Parcel;

import androidx.annotation.Keep;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RKP via {@code IRemotelyProvisionedComponent} HAL.
 * Shared crypto / HTTP / keybox helpers live in {@link rkp_v2}.
 */
public final class rkp_v1 {
    private static final String DESC =
            "android.hardware.security.keymint.IRemotelyProvisionedComponent";
    private static final String SVC =
            "android.hardware.security.keymint.IRemotelyProvisionedComponent/default";
    private static final String RKP_URL = rkp_v2.DEFAULT_URL;
    private static final byte[] HBK = new byte[32];
    private static final byte[] MAC_INFO = "Key to MAC public keys".getBytes(StandardCharsets.UTF_8);

    @Keep
    public static void main(final String[] args) {
        try {
            final String outputKeybox = args[0];
            System.out.println("out=" + outputKeybox);

            final KeyPair kp = rkp_v2.generateEcP256(new SecureRandom());
            final ECPublicKey pub = (ECPublicKey) kp.getPublic();
            final byte[] coseKey = rkp_v2.encodeCoseEc2P256(pub);
            final byte[] maced = macPublicKey(coseKey);
            System.out.println("maced=" + maced.length);

            final rkp_v2.EekChainResult eek = rkp_v2.fetchEekChain(
                    rkp_v2.fetchEekChainUrl(RKP_URL),
                    Build.FINGERPRINT,
                    rkp_v2.CONNECT_TIMEOUT_MS,
                    rkp_v2.READ_TIMEOUT_MS);
            System.out.println("challenge=" + eek.challenge.length);

            final AidlOut aidl = generateCertificateRequest(maced, eek.eekChain, eek.challenge);
            System.out.println("proxy=" + aidl.usedProxy);

            final byte[] csr = assembleCsr(
                    aidl.deviceInfo, eek.challenge, aidl.protectedData, aidl.macTag, maced);
            final List<byte[]> chains = rkp_v2.requestSignedCertificates(
                    rkp_v2.signCertificatesUrl(RKP_URL, eek.challenge),
                    csr,
                    rkp_v2. CONNECT_TIMEOUT_MS,
                    rkp_v2. READ_TIMEOUT_MS,
                    true);
            if (chains.isEmpty()) {
                throw new IllegalStateException("no certificate chains");
            }
            final List<X509Certificate> certs = rkp_v2.parseDerCerts(chains.get(0));
            System.out.println("chain certs=" + certs.size());

            final String xml = rkp_v2.buildKeybox((ECPrivateKey) kp.getPrivate(), pub, certs, "generic");
            rkp_v2.writeFile(new File(outputKeybox), xml.getBytes(StandardCharsets.UTF_8));
            System.out.println("OK");
        } catch (final Throwable tr) {
            System.out.println("ERROR " + tr);
            tr.printStackTrace(System.out);
            System.exit(1);
        }
    }

    /** COSE_Mac0 over the COSE_Key using HKDF(HBK, "Key to MAC public keys"). */
    static byte[] macPublicKey(final byte[] coseKey) throws Exception {
        final byte[] protectedHdr = new byte[]{(byte) 0xa1, 0x01, 0x05};
        final byte[] macKey = hkdfSha256(HBK, MAC_INFO, 32);
        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(macKey, "HmacSHA256"));
        final byte[] payloadBstr = rkp_v2.Cbor.encodeBstr(coseKey);
        final ByteArrayOutputStream full = new ByteArrayOutputStream();
        full.write(0x84);
        full.write(rkp_v2.Cbor.encodeTstr("MAC0"));
        full.write(rkp_v2.Cbor.encodeBstr(protectedHdr));
        full.write(rkp_v2.Cbor.encodeBstr(new byte[0]));
        full.write(payloadBstr, 0, payloadBstr.length);
        final byte[] tag = mac.doFinal(full.toByteArray());

        final ByteArrayOutputStream m0 = new ByteArrayOutputStream();
        m0.write(0x84);
        m0.write(rkp_v2.Cbor.encodeBstr(protectedHdr));
        m0.write(0xa0);
        m0.write(payloadBstr, 0, payloadBstr.length);
        m0.write(rkp_v2.Cbor.encodeBstr(tag));
        return m0.toByteArray();
    }

    private static final class AidlOut {
        final byte[] macTag;
        final byte[] deviceInfo;
        final byte[] protectedData;
        final boolean usedProxy;

        AidlOut(final byte[] macTag, final byte[] deviceInfo, final byte[] protectedData,
                final boolean usedProxy) {
            this.macTag = macTag;
            this.deviceInfo = deviceInfo;
            this.protectedData = protectedData;
            this.usedProxy = usedProxy;
        }
    }

    private static AidlOut generateCertificateRequest(
            final byte[] maced, final byte[] eekChain, final byte[] challenge) throws Exception {
        try {
            final IBinder b = getService();
            final Class<?> ifc = Class.forName(
                    "android.hardware.security.keymint.IRemotelyProvisionedComponent");
            final Class<?> stub = Class.forName(
                    "android.hardware.security.keymint.IRemotelyProvisionedComponent$Stub");
            final Object proxy = stub.getMethod("asInterface", IBinder.class).invoke(null, b);
            final Class<?> mpkCls = Class.forName(
                    "android.hardware.security.keymint.MacedPublicKey");
            final Object mpk = mpkCls.getDeclaredConstructor().newInstance();
            mpkCls.getField("macedKey").set(mpk, maced);
            final Object mpkArr = java.lang.reflect.Array.newInstance(mpkCls, 1);
            java.lang.reflect.Array.set(mpkArr, 0, mpk);
            final Class<?> diCls = Class.forName(
                    "android.hardware.security.keymint.DeviceInfo");
            final Class<?> pdCls = Class.forName(
                    "android.hardware.security.keymint.ProtectedData");
            final Object di = diCls.getDeclaredConstructor().newInstance();
            final Object pd = pdCls.getDeclaredConstructor().newInstance();
            final Method gen = ifc.getMethod(
                    "generateCertificateRequest",
                    boolean.class, mpkArr.getClass(), byte[].class, byte[].class, diCls, pdCls);
            final byte[] macTag =
                    (byte[]) gen.invoke(proxy, false, mpkArr, eekChain, challenge, di, pd);
            final byte[] diBytes = (byte[]) diCls.getField("deviceInfo").get(di);
            final byte[] pdBytes = (byte[]) pdCls.getField("protectedData").get(pd);
            return new AidlOut(macTag, diBytes, pdBytes, true);
        } catch (final Throwable proxyFail) {
            System.out.println("proxy-fallback: " + proxyFail);
            final IBinder b = getService();
            final Parcel data = Parcel.obtain();
            final Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(DESC);
                data.writeInt(0);
                data.writeInt(1);
                data.writeInt(1);
                data.writeInt(0);
                data.writeByteArray(maced);
                data.writeByteArray(eekChain);
                data.writeByteArray(challenge);
                b.transact(3, data, reply, 0);
                reply.readException();
                final byte[] macTag = reply.createByteArray();
                final byte[] diBytes;
                if (reply.readInt() != 0) {
                    reply.readInt();
                    diBytes = reply.createByteArray();
                } else {
                    diBytes = new byte[0];
                }
                final byte[] pdBytes;
                if (reply.readInt() != 0) {
                    reply.readInt();
                    pdBytes = reply.createByteArray();
                } else {
                    pdBytes = new byte[0];
                }
                return new AidlOut(macTag, diBytes, pdBytes, false);
            } finally {
                data.recycle();
                reply.recycle();
            }
        }
    }

    private static IBinder getService() throws Exception {
        final Class<?> sm = Class.forName("android.os.ServiceManager");
        return (IBinder) sm.getMethod("getService", String.class).invoke(null, SVC);
    }

    private static byte[] assembleCsr(
            final byte[] di,
            final byte[] challenge,
            final byte[] pd,
            final byte[] macTag,
            final byte[] maced) {
        final Object decoded = rkp_v2.Cbor.decode(maced);
        if (!(decoded instanceof List<?> m0a) || m0a.size() < 3) {
            throw new IllegalStateException("maced: expected MAC0 array");
        }
        if (!(m0a.get(0) instanceof byte[] protectedHdr) || !(m0a.get(2) instanceof byte[] payload)) {
            throw new IllegalStateException("maced: bad MAC0 fields");
        }
        final byte[] newPayload = rkp_v2.Cbor.encodeCborArray(new byte[][]{payload});

        final ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x84);
        o.write(0x82);
        o.write(di, 0, di.length);
        o.write(0xa0);
        final byte[] chb = rkp_v2.Cbor.encodeBstr(challenge);
        o.write(chb, 0, chb.length);
        o.write(pd, 0, pd.length);
        o.write(0x84);
        final byte[] ph = rkp_v2.Cbor.encodeBstr(protectedHdr);
        o.write(ph, 0, ph.length);
        o.write(0xa0);
        final byte[] np = rkp_v2.Cbor.encodeBstr(newPayload);
        o.write(np, 0, np.length);
        final byte[] tagB = rkp_v2.Cbor.encodeBstr(macTag);
        o.write(tagB, 0, tagB.length);
        return o.toByteArray();
    }

    private static byte[] hkdfSha256(final byte[] ikm, final byte[] info, final int len)
            throws Exception {
        final Mac ex = Mac.getInstance("HmacSHA256");
        ex.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        final byte[] prk = ex.doFinal(ikm);
        final ByteArrayOutputStream t = new ByteArrayOutputStream();
        byte[] prev = new byte[0];
        int counter = 1;
        while (t.size() < len) {
            final Mac mc = Mac.getInstance("HmacSHA256");
            mc.init(new SecretKeySpec(prk, "HmacSHA256"));
            mc.update(prev);
            mc.update(info);
            mc.update((byte) counter++);
            prev = mc.doFinal();
            t.write(prev, 0, Math.min(prev.length, len - t.size()));
        }
        return t.toByteArray();
    }
}
