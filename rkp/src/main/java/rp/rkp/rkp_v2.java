package rp.rkp;

import android.os.Build;
import android.util.Base64;
import android.util.Log;

import com.xuexiang.xui.widget.textview.LoggerTextView;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class rkp_v2 {
    private static final String TAG = "Rkp";
    public static final String DEFAULT_URL = "https://remoteprovisioning.grapheneos.org/v1";
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    static final int CONNECT_TIMEOUT_MS = 15_000;
    static final int READ_TIMEOUT_MS = 20_000;

    public static final class Config {
        public String rkpUrl = DEFAULT_URL;
        public String fingerprint = Build.FINGERPRINT;
        public String deviceId = "generic";
        public String kmcliPath;
        public File outDir;
    }

    public static final class Result {
        public File keyboxXml;
        public File privateKeyPem;
        public File csrCbor;
        public final List<X509Certificate> chain = new ArrayList<>();
    }

    public static Result run(final Config cfg, final LoggerTextView logger, final String su) throws Exception {
        if (cfg.outDir == null) {
            throw new IllegalArgumentException("outDir required");
        }
        if (!cfg.outDir.exists() && !cfg.outDir.mkdirs()) {
            throw new IllegalStateException("cannot create outDir: " + cfg.outDir);
        }

        logger.logNormal("[1] P-256 keypair");
        final KeyPair kp = generateEcP256();
        final byte[] coseKey = encodeCoseEc2P256((ECPublicKey) kp.getPublic());

        logger.logNormal("[2] fetchEekChain");
        if (cfg.fingerprint == null || cfg.fingerprint.isEmpty()) {
            throw new IllegalStateException("empty fingerprint");
        }
        logger.logNormal("fingerprint=" + cfg.fingerprint);
        final EekChainResult eek = fetchEekChain(
                fetchEekChainUrl(cfg.rkpUrl), cfg.fingerprint, READ_TIMEOUT_MS);
        final byte[] challenge = eek.challenge;
        logger.logNormal("challenge " + challenge.length + "B");
        if (challenge.length > 64) {
            throw new IllegalStateException("challenge too long");
        }

        logger.logNormal("[3] kmcli 0x3122");
        final byte[] nested = Cbor.encodeCborArray(new byte[][]{coseKey});
        final byte[] req = Cbor.encodeMap(new Object[]{4, challenge}, new Object[]{57, nested});
        final String hex = toHex(req);
        final File csrFile = new File(cfg.outDir, "csr.bin");
        String out = execAs(su, new String[]{
                "export LD_LIBRARY_PATH=/system/lib64:/vendor/lib64",
                "chmod +x " + shq(cfg.kmcliPath),
                shq(cfg.kmcliPath) + " 3122 " + hex + ' ' + shq(csrFile.getPath()),
        });
        if (out == null) {
            throw new IllegalStateException("su failed");
        }
        logger.logNormal(out.trim());
        if (!out.contains("retcode = 0x00000000")) {
            out = execAs(su, new String[]{
                    "export LD_LIBRARY_PATH=/system/lib64:/vendor/lib64:/vendor/lib64/hw",
                    "KmInstallKeybox Keybox_file Device_ID true rkp",
                    shq(cfg.kmcliPath) + " 3122 " + hex + ' ' + shq(csrFile.getPath()),
            });
            if (out == null) {
                throw new IllegalStateException("su failed");
            }
            logger.logNormal(out.trim());
            if (!out.contains("retcode = 0x00000000")) {
                throw new IllegalStateException("TA rejected:\n" + tail(out));
            }
        }

        byte[] csr = readFile(csrFile);
        final Object top = Cbor.decode(csr);
        if (top instanceof Map) {
            final Object v = ((Map<?, ?>) top).get(61);
            if (!(v instanceof byte[])) {
                throw new IllegalStateException("CSR map missing key 61; keys=" + ((Map<?, ?>) top).keySet());
            }
            csr = (byte[]) v;
        }
        logger.logNormal("CSR " + csr.length + "B");
        final File csrOut = new File(cfg.outDir, "oracle_csr.cbor");
        writeFile(csrOut, csr);

        logger.logNormal("[4] signCertificates");
        final List<byte[]> chains = requestSignedCertificates(cfg.rkpUrl, csr, challenge, READ_TIMEOUT_MS);
        if (chains.isEmpty()) {
            throw new IllegalStateException("no chains");
        }
        final List<X509Certificate> certs = parseDerCerts(chains.get(0));
        for (final X509Certificate c : certs) {
            logger.logNormal(c.getSubjectDN().getName());
        }

        logger.logNormal("[5] keybox.xml");
        final ECPrivateKey priv = (ECPrivateKey) kp.getPrivate();
        final ECPublicKey pub = (ECPublicKey) kp.getPublic();
        final String xml = buildKeybox(priv, pub, certs, cfg.deviceId);
        final File kb = new File(cfg.outDir, "keybox.xml");
        final File pem = new File(cfg.outDir, "keybox_priv.pem");
        writeFile(kb, xml.getBytes(StandardCharsets.UTF_8));
        writeFile(pem, ecPrivateKeyPem(priv, pub).getBytes(StandardCharsets.UTF_8));

        final Result r = new Result();
        r.keyboxXml = kb;
        r.privateKeyPem = pem;
        r.csrCbor = csrOut;
        r.chain.addAll(certs);
        logger.logNormal("[+] " + kb);
        logger.logNormal("[+] " + pem);
        return r;
    }

    public static KeyPair generateEcP256() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    /**
     * Same as ori rkp_v1: explicit SecureRandom.
     */
    public static KeyPair generateEcP256(final SecureRandom random) throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"), random);
        return kpg.generateKeyPair();
    }

    public static byte[] encodeCoseEc2P256(final ECPublicKey pub) {
        final ECPoint p = pub.getW();
        final byte[] x = toFixed32Bytes(p.getAffineX());
        final byte[] y = toFixed32Bytes(p.getAffineY());
        final LinkedHashMap<Object, Object> m = new LinkedHashMap<>();
        m.put(1, 2);
        m.put(3, -7);
        m.put(-1, 1);
        m.put(-2, x);
        m.put(-3, y);
        return Cbor.encodeMap(m);
    }

    private static byte[] toFixed32Bytes(final BigInteger v) {
        final byte[] raw = v.toByteArray();
        final byte[] out = new byte[32];
        if (raw.length > 32) {
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        } else {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        }
        return out;
    }

    /**
     * SEC1 EC PRIVATE KEY PEM (matches cryptography TraditionalOpenSSL).
     */
    private static String ecPrivateKeyPem(final ECPrivateKey priv, final ECPublicKey pub) {
        final byte[] d = toFixed32Bytes(priv.getS());
        final ECPoint p = pub.getW();
        final byte[] x = toFixed32Bytes(p.getAffineX());
        final byte[] y = toFixed32Bytes(p.getAffineY());
        final byte[] pubUncompressed = new byte[65];
        pubUncompressed[0] = 0x04;
        System.arraycopy(x, 0, pubUncompressed, 1, 32);
        System.arraycopy(y, 0, pubUncompressed, 33, 32);

        final byte[] oid = new byte[]{
                0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07
        };
        final byte[] version = new byte[]{0x02, 0x01, 0x01};
        final byte[] octD = derOctetString(d);
        final byte[] ctx0 = derContext(0, oid);
        final byte[] bitPub = derBitString(pubUncompressed);
        final byte[] ctx1 = derContext(1, bitPub);
        return pemBlock("EC PRIVATE KEY", derSequence(concat(version, octD, ctx0, ctx1)));
    }

    private static byte[] derSequence(final byte[] body) {
        return concat(new byte[]{0x30}, derLen(body.length), body);
    }

    private static byte[] derOctetString(final byte[] v) {
        return concat(new byte[]{0x04}, derLen(v.length), v);
    }

    private static byte[] derBitString(final byte[] v) {
        final byte[] content = new byte[v.length + 1];
        content[0] = 0x00;
        System.arraycopy(v, 0, content, 1, v.length);
        return concat(new byte[]{0x03}, derLen(content.length), content);
    }

    private static byte[] derContext(final int n, final byte[] inner) {
        return concat(new byte[]{(byte) (0xa0 | n)}, derLen(inner.length), inner);
    }

    private static byte[] derLen(final int len) {
        if (len < 0x80) {
            return new byte[]{(byte) len};
        }
        if (len <= 0xff) {
            return new byte[]{(byte) 0x81, (byte) len};
        }
        return new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) len};
    }

    private static String pemBlock(final String type, final byte[] der) {
        final String b64 = Base64.encodeToString(der, Base64.NO_WRAP);
        final StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END ").append(type).append("-----\n");
        return sb.toString();
    }

    /**
     * {@code rkpBaseUrl + ":fetchEekChain"}
     */
    public static String fetchEekChainUrl(final String rkpBaseUrl) {
        return rkpBaseUrl + ":fetchEekChain";
    }

    /**
     * {@code rkpBaseUrl + ":signCertificates?challenge=" + urlSafeBase64(challenge)}
     */
    public static String signCertificatesUrl(final String rkpBaseUrl, final byte[] challenge) {
        final String q = Base64.encodeToString(
                challenge, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        return rkpBaseUrl + ":signCertificates?challenge=" + q;
    }

    /**
     * Result of {@link #fetchEekChain}: server challenge + EEK certificate chain CBOR.
     */
    public static final class EekChainResult {
        public final byte[] challenge;
        public final byte[] eekChain;

        public EekChainResult(final byte[] challenge, final byte[] eekChain) {
            this.challenge = challenge;
            this.eekChain = eekChain;
        }
    }

    public static EekChainResult fetchEekChain(
            final String fetchEekChainUrl, final String fingerprint, final int httpTimeoutMs)
            throws Exception {
        return fetchEekChain(fetchEekChainUrl, fingerprint, httpTimeoutMs, httpTimeoutMs);
    }

    /**
     * POST fetchEekChain. Prefer EEK alg == 2; otherwise first chain.
     * {@link EekChainResult#eekChain} is the original CBOR slice (KeyMint verifies it).
     */
    public static EekChainResult fetchEekChain(
            final String fetchEekChainUrl,
            final String fingerprint,
            final int connectTimeoutMs,
            final int readTimeoutMs)
            throws Exception {
        if (fingerprint == null || fingerprint.isEmpty()) {
            throw new IllegalStateException("empty fingerprint");
        }
        final LinkedHashMap<Object, Object> body = new LinkedHashMap<>();
        body.put("fingerprint", fingerprint);
        body.put("id", 42);
        final byte[] resp = httpPost(
                fetchEekChainUrl, Cbor.encodeMap(body), connectTimeoutMs, readTimeoutMs);
        return parseEekChainResponse(resp);
    }

    private static EekChainResult parseEekChainResponse(final byte[] resp) {
        final RawCbor.Value root = RawCbor.parse(resp);
        final RawCbor.Value[] arr = root.asArray();
        if (arr.length < 2) {
            throw new IllegalStateException("fetchEekChain: expected array");
        }
        final byte[] challenge = arr[1].asBytes();
        final RawCbor.Value[] chainsArr = arr[0].asArray();
        byte[] eekChain = null;
        for (final RawCbor.Value ce : chainsArr) {
            final RawCbor.Value[] pair = ce.asArray();
            if (pair.length >= 2 && pair[0].asInt() == 2) {
                eekChain = pair[1].raw();
                break;
            }
        }
        if (eekChain == null && chainsArr.length > 0) {
            eekChain = chainsArr[0].asArray()[1].raw();
        }
        if (eekChain == null) {
            throw new IllegalStateException("fetchEekChain: missing eek chain");
        }
        return new EekChainResult(challenge, eekChain);
    }

    /**
     * Minimal CBOR parser that preserves original byte slices via {@link Value#raw()}.
     */
    private static final class RawCbor {
        private RawCbor() {
        }

        public static Value parse(final byte[] b) {
            return new Parser(b).parseOne();
        }

        public static final class Value {
            final int major;
            final Object value;
            final byte[] raw;

            private Value(final int major, final Object value, final byte[] raw) {
                this.major = major;
                this.value = value;
                this.raw = raw;
            }

            public long asInt() {
                if (value instanceof Long) {
                    return (Long) value;
                }
                if (value instanceof Integer) {
                    return (Integer) value;
                }
                throw new ClassCastException(
                        "asInt: " + (value == null ? "null" : value.getClass()));
            }

            public byte[] asBytes() {
                return (byte[]) value;
            }

            @SuppressWarnings("unchecked")
            public Value[] asArray() {
                return ((List<Value>) value).toArray(new Value[0]);
            }

            public byte[] raw() {
                return raw.clone();
            }
        }

        private static final class Parser {
            private final byte[] buf;
            private int pos;

            Parser(final byte[] b) {
                buf = b;
            }

            Value parseOne() {
                final int start = pos;
                final int ib = buf[pos++] & 0xff;
                final int major = ib >> 5;
                long info = ib & 0x1f;
                if (info == 24) {
                    info = buf[pos++] & 0xff;
                } else if (info == 25) {
                    info = ((buf[pos] & 0xff) << 8) | (buf[pos + 1] & 0xff);
                    pos += 2;
                } else if (info == 26) {
                    info = ((long) (buf[pos] & 0xff) << 24)
                            | ((buf[pos + 1] & 0xff) << 16)
                            | ((buf[pos + 2] & 0xff) << 8)
                            | (buf[pos + 3] & 0xff);
                    pos += 4;
                } else if (info >= 28) {
                    throw new RuntimeException("unsupported cbor info " + info);
                }

                switch (major) {
                    case 0:
                        return finish(major, info, start);
                    case 1:
                        return finish(major, -1 - info, start);
                    case 2: {
                        final byte[] b = new byte[(int) info];
                        System.arraycopy(buf, pos, b, 0, (int) info);
                        pos += (int) info;
                        return finish(major, b, start);
                    }
                    case 3: {
                        final byte[] b = new byte[(int) info];
                        System.arraycopy(buf, pos, b, 0, (int) info);
                        pos += (int) info;
                        return finish(major, new String(b, StandardCharsets.UTF_8), start);
                    }
                    case 4: {
                        final List<Value> l = new ArrayList<>();
                        for (long i = 0; i < info; i++) {
                            l.add(parseOne());
                        }
                        return finish(major, l, start);
                    }
                    case 5: {
                        final List<Value> l = new ArrayList<>();
                        for (long i = 0; i < info; i++) {
                            l.add(parseOne());
                            l.add(parseOne());
                        }
                        return finish(major, l, start);
                    }
                    case 7:
                        return finish(major, info == 20 ? Boolean.FALSE : Boolean.TRUE, start);
                    default:
                        throw new RuntimeException("bad major " + major);
                }
            }

            private Value finish(final int major, final Object v, final int start) {
                final byte[] raw = new byte[pos - start];
                System.arraycopy(buf, start, raw, 0, raw.length);
                return new Value(major, v, raw);
            }
        }
    }

    /**
     * POST CSR to signCertificates (colon URL). Certificate blob order: shared || leaf.
     */
    public static List<byte[]> requestSignedCertificates(
            final String rkpBaseUrl,
            final byte[] csr,
            final byte[] challenge,
            final int httpTimeoutMs)
            throws Exception {
        return requestSignedCertificates(
                signCertificatesUrl(rkpBaseUrl, challenge),
                csr,
                httpTimeoutMs,
                httpTimeoutMs,
                false);
    }

    /**
     * POST CSR to a full signCertificates URL.
     *
     * @param leafBeforeShared true → leaf||shared (rkp_v1 keybox); false → shared||leaf (rkp_v2)
     */
    public static List<byte[]> requestSignedCertificates(
            final String signCertificatesUrl,
            final byte[] csr,
            final int connectTimeoutMs,
            final int readTimeoutMs,
            final boolean leafBeforeShared)
            throws Exception {
        final byte[] data;
        try {
            data = httpPost(signCertificatesUrl, csr, connectTimeoutMs, readTimeoutMs);
        } catch (final HttpStatusException e) {
            throw new IllegalStateException("HTTP " + e.code + ": " + e.body, e);
        }
        return parseSignedCertificateChains(data, leafBeforeShared);
    }

    private static List<byte[]> parseSignedCertificateChains(
            final byte[] data, final boolean leafBeforeShared) {
        final Object result = Cbor.decode(data);
        if (!(result instanceof List<?> top) || top.isEmpty()) {
            return new ArrayList<>();
        }
        final Object first = top.get(0);
        final List<?> inner = first instanceof List ? (List<?>) first : top;
        if (inner.size() < 2) {
            return new ArrayList<>();
        }
        final byte[] shared = inner.get(0) instanceof byte[] ? (byte[]) inner.get(0) : new byte[0];
        final Object ucObj = inner.get(1);
        if (!(ucObj instanceof List)) {
            return new ArrayList<>();
        }
        final List<byte[]> chains = new ArrayList<>();
        for (final Object uc : (List<?>) ucObj) {
            if (uc instanceof byte[] leaf) {
                chains.add(leafBeforeShared ? concat(leaf, shared) : concat(shared, leaf));
            }
        }
        return chains;
    }

    private static byte[] httpPost(final String urlStr, final byte[] body, final int httpTimeoutMs)
            throws Exception {
        return httpPost(urlStr, body, httpTimeoutMs, httpTimeoutMs);
    }

    private static byte[] httpPost(
            final String urlStr,
            final byte[] body,
            final int connectTimeoutMs,
            final int readTimeoutMs)
            throws Exception {
        final HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setConnectTimeout(connectTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/cbor");
        conn.setRequestProperty("Accept", "application/cbor");
        try (final OutputStream os = conn.getOutputStream()) {
            os.write(body);
        }
        final int code = conn.getResponseCode();
        final InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        if (is == null) {
            throw new HttpStatusException(code, "");
        }
        final byte[] resp = readAll(is);
        if (code >= 400) {
            final String msg = new String(resp, 0, Math.min(1024, resp.length), StandardCharsets.UTF_8);
            throw new HttpStatusException(code, msg);
        }
        return resp;
    }

    private static final class HttpStatusException extends Exception {
        final int code;
        final String body;

        HttpStatusException(final int code, final String body) {
            this.code = code;
            this.body = body;
        }
    }

    public static List<X509Certificate> parseDerCerts(final byte[] data) throws Exception {
        final List<X509Certificate> certs = new ArrayList<>();
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        int pos = 0;
        while (pos < data.length && (data[pos] & 0xff) == 0x30) {
            final int length;
            final int hdr;
            final int b1 = data[pos + 1] & 0xff;
            if ((b1 & 0x80) != 0) {
                final int n = b1 & 0x7f;
                int len = 0;
                for (int i = 0; i < n; i++) {
                    len = (len << 8) | (data[pos + 2 + i] & 0xff);
                }
                length = len;
                hdr = 2 + n;
            } else {
                length = b1;
                hdr = 2;
            }
            final int end = pos + hdr + length;
            if (end > data.length) {
                break;
            }
            final byte[] chunk = Arrays.copyOfRange(data, pos, end);
            try {
                certs.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(chunk)));
            } catch (final Exception e) {
                break;
            }
            pos = end;
        }
        return certs;
    }

    private static List<X509Certificate> sortChain(final List<X509Certificate> certs) {
        if (certs.size() <= 1) {
            return new ArrayList<>(certs);
        }
        final Map<String, X509Certificate> bySubj = new HashMap<>();
        final Set<String> issuers = new HashSet<>();
        for (final X509Certificate c : certs) {
            bySubj.put(c.getSubjectDN().getName(), c);
            if (!c.getIssuerDN().getName().equals(c.getSubjectDN().getName())) {
                issuers.add(c.getIssuerDN().getName());
            }
        }
        X509Certificate leaf = null;
        for (final X509Certificate c : certs) {
            if (!issuers.contains(c.getSubjectDN().getName())) {
                leaf = c;
                break;
            }
        }
        if (leaf == null) {
            return new ArrayList<>(certs);
        }
        final List<X509Certificate> ordered = new ArrayList<>();
        final Set<String> seen = new HashSet<>();
        X509Certificate cur = leaf;
        ordered.add(cur);
        seen.add(cur.getSubjectDN().getName());
        while (ordered.size() < certs.size()) {
            final String iss = cur.getIssuerDN().getName();
            if (!bySubj.containsKey(iss) || seen.contains(iss)) {
                break;
            }
            cur = bySubj.get(iss);
            ordered.add(cur);
            assert cur != null;
            seen.add(cur.getSubjectDN().getName());
        }
        for (final X509Certificate c : certs) {
            if (!seen.contains(c.getSubjectDN().getName())) {
                ordered.add(c);
            }
        }
        return ordered;
    }

    public static String buildKeybox(
            final ECPrivateKey priv,
            final ECPublicKey pub,
            final List<X509Certificate> certsIn,
            final String deviceId)
            throws Exception {
        final List<X509Certificate> certs = sortChain(certsIn);
        final String i1 = "    ";
        final String i2 = "        ";
        final String i3 = "            ";
        final StringBuilder sb = new StringBuilder();
        sb.append("<?xml version=\"1.0\"?>\n");
        sb.append("<AndroidAttestation>\n");
        sb.append(i1).append("<NumberOfKeyboxes>1</NumberOfKeyboxes>\n");
        sb.append(i1).append("<Keybox DeviceID=\"").append(xmlEsc(deviceId)).append("\">\n");
        sb.append(i2).append("<Key algorithm=\"ecdsa\">\n");
        sb.append(i2).append("    <PrivateKey format=\"pem\">\n");
        sb.append(indentPem(ecPrivateKeyPem(priv, pub), i2 + "    "));
        sb.append(i2).append("    </PrivateKey>\n");
        sb.append(i2).append("    <CertificateChain>\n");
        sb.append(i3).append("<NumberOfCertificates>").append(certs.size()).append("</NumberOfCertificates>\n");
        for (final X509Certificate c : certs) {
            final String pem = pemBlock("CERTIFICATE", c.getEncoded());
            sb.append(i3).append("<Certificate format=\"pem\">\n");
            sb.append(indentPem(pem, i3 + "    "));
            sb.append(i3).append("</Certificate>\n");
        }
        sb.append(i2).append("    </CertificateChain>\n");
        sb.append(i2).append("</Key>\n");
        sb.append(i1).append("</Keybox>\n");
        sb.append("</AndroidAttestation>\n");
        return sb.toString();
    }

    private static String indentPem(final String pem, final String ind) {
        final StringBuilder sb = new StringBuilder();
        for (final String ln : pem.trim().split("\n", -1)) {
            if (ln.trim().isEmpty()) {
                sb.append('\n');
            } else {
                sb.append(ind).append(ln).append('\n');
            }
        }
        return sb.toString();
    }

    private static String xmlEsc(final String s) {
        return s.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;");
    }

    private static String execAs(final String su, final String[] commands) {
        try {
            final Process process = Runtime.getRuntime().exec(su);
            try (final DataOutputStream os = new DataOutputStream(process.getOutputStream())) {
                for (final String command : commands) {
                    if (command != null) {
                        os.writeBytes(command.trim());
                        os.writeBytes("\n");
                        os.flush();
                    }
                }
                os.writeBytes("exit\n");
                os.flush();
            }
            process.waitFor();
            return new String(readAll(process.getInputStream()), StandardCharsets.UTF_8);
        } catch (final Exception e) {
            Log.e(TAG, "execAsSu", e);
            return null;
        }
    }

    private static String shq(final String s) {
        final char q = '\'';
        return q + s.replace("'", "'\\''") + q;
    }

    private static String tail(final String s) {
        return s.length() <= 2000 ? s : s.substring(s.length() - 2000);
    }

    private static byte[] readFile(final File f) throws Exception {
        try (final FileInputStream in = new FileInputStream(f)) {
            return readAll(in);
        }
    }

    public static void writeFile(final File f, final byte[] data) throws Exception {
        try (final FileOutputStream out = new FileOutputStream(f)) {
            out.write(data);
        }
    }

    private static byte[] readAll(final InputStream in) throws Exception {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        final byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) >= 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    private static byte[] concat(final byte[]... parts) {
        int n = 0;
        for (final byte[] p : parts) {
            n += p.length;
        }
        final byte[] out = new byte[n];
        int o = 0;
        for (final byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    private static String toHex(final byte[] data) {
        final char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            final int v = data[i] & 0xff;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0f];
        }
        return new String(out);
    }

    /**
     * Minimal CBOR for maps / arrays / text / bytes / ints.
     */
    public static final class Cbor {
        private Cbor() {
        }

        static byte[] encodeMap(final LinkedHashMap<Object, Object> map) {
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            writeMap(bos, map);
            return bos.toByteArray();
        }

        /**
         * Encode map from (key, value) pairs.
         */
        static byte[] encodeMap(final Object[]... pairs) {
            final LinkedHashMap<Object, Object> m = new LinkedHashMap<>();
            for (final Object[] p : pairs) {
                m.put(p[0], p[1]);
            }
            return encodeMap(m);
        }

        /**
         * CBOR array of already-encoded CBOR items.
         */
        public static byte[] encodeCborArray(final byte[][] items) {
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            writeHead(bos, 4, items.length);
            for (final byte[] it : items) {
                bos.write(it, 0, it.length);
            }
            return bos.toByteArray();
        }


        public static byte[] encodeBstr(final byte[] b) {
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            writeHead(bos, 2, b.length);
            bos.write(b, 0, b.length);
            return bos.toByteArray();
        }

        public static byte[] encodeTstr(final String s) {
            final byte[] b = s.getBytes(StandardCharsets.UTF_8);
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            writeHead(bos, 3, b.length);
            bos.write(b, 0, b.length);
            return bos.toByteArray();
        }

        public static Object decode(final byte[] data) {
            return new Decoder(data).read();
        }

        private static void writeMap(final ByteArrayOutputStream bos, final LinkedHashMap<Object, Object> map) {
            writeHead(bos, 5, map.size());
            for (final Map.Entry<Object, Object> e : map.entrySet()) {
                writeValue(bos, e.getKey());
                writeValue(bos, e.getValue());
            }
        }

        private static void writeValue(final ByteArrayOutputStream bos, final Object v) {
            switch (v) {
                case byte[] b -> {
                    writeHead(bos, 2, b.length);
                    bos.write(b, 0, b.length);
                }
                case String s -> {
                    final byte[] b = s.getBytes(StandardCharsets.UTF_8);
                    writeHead(bos, 3, b.length);
                    bos.write(b, 0, b.length);
                }
                case Integer i -> writeInt(bos, i.longValue());
                case Long l -> writeInt(bos, l);
                case List<?> list -> {
                    writeHead(bos, 4, list.size());
                    for (final Object o : list) {
                        writeValue(bos, o);
                    }
                }
                case LinkedHashMap<?, ?> ignored -> {
                    @SuppressWarnings("unchecked") final LinkedHashMap<Object, Object> m = (LinkedHashMap<Object, Object>) v;
                    writeMap(bos, m);
                }
                default ->
                        throw new IllegalArgumentException("unsupported CBOR type: " + v.getClass());
            }
        }

        private static void writeInt(final ByteArrayOutputStream bos, final long v) {
            if (v >= 0) {
                writeHead(bos, 0, v);
            } else {
                writeHead(bos, 1, -1L - v);
            }
        }

        private static void writeHead(final ByteArrayOutputStream bos, final int major, final long n) {
            final int mt = major << 5;
            if (n < 24) {
                bos.write(mt | (int) n);
            } else if (n < 256) {
                bos.write(mt | 24);
                bos.write((int) n);
            } else if (n < 65536) {
                bos.write(mt | 25);
                bos.write((int) (n >> 8));
                bos.write((int) n);
            } else if (n < 0x100000000L) {
                bos.write(mt | 26);
                bos.write((int) (n >> 24));
                bos.write((int) (n >> 16));
                bos.write((int) (n >> 8));
                bos.write((int) n);
            } else {
                bos.write(mt | 27);
                for (int i = 56; i >= 0; i -= 8) {
                    bos.write((int) (n >> i));
                }
            }
        }

        private static final class Decoder {
            private final byte[] data;
            private int pos;

            Decoder(final byte[] data) {
                this.data = data;
            }

            Object read() {
                final int ib = data[pos++] & 0xff;
                final int major = ib >> 5;
                final long ai = additional(ib & 0x1f);
                switch (major) {
                    case 0:
                        // Must not use int/long ternary — promotes to Long and breaks Map.get(61).
                        if (ai <= Integer.MAX_VALUE) {
                            return (int) ai;
                        }
                        return ai;
                    case 1: {
                        final long n = -1L - ai;
                        if (n >= Integer.MIN_VALUE && n <= Integer.MAX_VALUE) {
                            return (int) n;
                        }
                        return n;
                    }
                    case 2: {
                        final int len = (int) ai;
                        final byte[] b = Arrays.copyOfRange(data, pos, pos + len);
                        pos += len;
                        return b;
                    }
                    case 3: {
                        final int len = (int) ai;
                        final String s = new String(data, pos, len, StandardCharsets.UTF_8);
                        pos += len;
                        return s;
                    }
                    case 4: {
                        final int len = (int) ai;
                        final List<Object> list = new ArrayList<>(len);
                        for (int i = 0; i < len; i++) {
                            list.add(read());
                        }
                        return list;
                    }
                    case 5: {
                        final int len = (int) ai;
                        final LinkedHashMap<Object, Object> map = new LinkedHashMap<>();
                        for (int i = 0; i < len; i++) {
                            final Object k = read();
                            final Object val = read();
                            map.put(k, val);
                        }
                        return map;
                    }
                    default:
                        throw new IllegalArgumentException("unsupported major type " + major);
                }
            }

            private long additional(final int ai) {
                if (ai < 24) {
                    return ai;
                }
                if (ai == 24) {
                    return data[pos++] & 0xff;
                }
                if (ai == 25) {
                    final long v = ((data[pos] & 0xffL) << 8) | (data[pos + 1] & 0xffL);
                    pos += 2;
                    return v;
                }
                if (ai == 26) {
                    final long v = ((data[pos] & 0xffL) << 24)
                            | ((data[pos + 1] & 0xffL) << 16)
                            | ((data[pos + 2] & 0xffL) << 8)
                            | (data[pos + 3] & 0xffL);
                    pos += 4;
                    return v;
                }
                if (ai == 27) {
                    long v = 0;
                    for (int i = 0; i < 8; i++) {
                        v = (v << 8) | (data[pos++] & 0xffL);
                    }
                    return v;
                }
                throw new IllegalArgumentException("indefinite / reserved ai=" + ai);
            }
        }
    }
}
