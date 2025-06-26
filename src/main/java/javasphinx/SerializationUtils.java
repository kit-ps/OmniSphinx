package javasphinx;

import javasphinx.crypto.ECCGroup;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * Class to house various utility methods.
 */
public final class SerializationUtils {

    private SerializationUtils() {
    }
    /**
     * Concatenate the provided byte arrays into one byte array.
     * @param arrays Array of byte arrays.
     * @return Byte array resulted from concatenating the inputs.
     */
    public static byte[] concatenate(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }

        byte[] result = new byte[length];

        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }

        return result;
    }

    public static byte[] encodeUuid(UUID uuid) {
        return concatenate(encodeLong(uuid.getMostSignificantBits()), encodeLong(uuid.getLeastSignificantBits()));
    }

    public static UUID decodeUuid(byte[] array) {
        final var mostSigBits = decodeLong(slice(array, 4));
        final var leastSigBits = decodeLong(slice(array, 4, 8));
        return new UUID(mostSigBits, leastSigBits);
    }

    /**
     * Decode an elliptic curve point from its binary representation.
     * @param encodedECPoint Binary representation of an elliptic curve point.
     * @return Elliptic curve point as the ECPoint type.
     */
    public static ECPoint decodeECPoint(byte[] encodedECPoint) {
        ECCurve ecCurve = ECNamedCurveTable.getParameterSpec(ECCGroup.DEFAULT_CURVE_NAME).getCurve();
        return ecCurve.decodePoint(encodedECPoint);
    }

    public static byte[] encodeECPoint(ECPoint point) {
        return point.getEncoded(true);
    }

    public static String base64encode(byte[] bytes) {
        return Base64.toBase64String(bytes);
    }

    public static byte[] base64decode(String encodedByteArray) {
        return Base64.decode(encodedByteArray);
    }

    public static byte[] encodeLong(long value) {
        ByteBuffer b = ByteBuffer.allocate(8);
        b.putLong(value);
        return b.array();
    }

    public static long decodeLong(byte[] array) {
        ByteBuffer b = ByteBuffer.wrap(array);
        return b.getLong();
    }

    public static byte[] encodeInt(int value) {
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(value);
        return b.array();
    }

    public static int decodeInt(byte[] array) {
        ByteBuffer b = ByteBuffer.wrap(array);
        return b.getInt();
    }

    /**
     * Create a contiguous subarray from the index start to the index (end - 1) of the source array. Operates like Python's slicing syntax.
     * @param source Source array.
     * @param start Starting index.
     * @param end Ending index + 1;
     * @return Contiguous subarray from the index start to the index (end - 1) of the source array.
     */
    public static byte[] slice(byte[] source, int start, int end) {
        int resultLength = end - start;
        byte[] result = new byte[resultLength];
        System.arraycopy(source, start, result, 0, resultLength);
        return result;
    }

    /**
     * Create a contiguous subarray from the index 0 to the index (end - 1) of the source array. Operates like Python's slicing syntax.
     * @param source Source array.
     * @param end Starting index.
     * @return Contiguous subarray from the index 0 to the index (end - 1) of the source array.
     */
    public static byte[] slice(byte[] source, int end) {
        return slice(source, 0, end);
    }
}
