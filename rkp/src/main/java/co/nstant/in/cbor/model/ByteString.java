package co.nstant.in.cbor.model;

import androidx.annotation.NonNull;

import java.util.Arrays;

public class ByteString extends ChunkableDataItem {

    private final byte[] bytes;

    public ByteString(byte[] bytes) {
        super(MajorType.BYTE_STRING);
        if (bytes == null) {
            this.bytes = null;
        } else {
            this.bytes = bytes;
        }
    }

    public byte[] getBytes() {
        if (bytes == null) {
            return null;
        } else {
            return bytes;
        }
    }

    @Override
    public boolean equals(Object object) {
        if (object instanceof ByteString) {
            ByteString other = (ByteString) object;
            return super.equals(object) && Arrays.equals(bytes, other.bytes);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return super.hashCode() ^ Arrays.hashCode(bytes);
    }

    @NonNull
    @Override
    public String toString() {
        return bytes != null && bytes.length <= 128 ? bytesToHex(bytes) : "<byte-string>";
    }

    private static final char[] HEX_CHAR_ARRAY = "0123456789abcdef".toCharArray();

    public static String bytesToHex(@NonNull byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_CHAR_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_CHAR_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
