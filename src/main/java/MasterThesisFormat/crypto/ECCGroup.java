package MasterThesisFormat.crypto;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;

/**
 * Class to represent an elliptic curve group and providing methods for cryptographic computations.
 */
public class ECCGroup {
    public static final String DEFAULT_CURVE_NAME = "secp224r1";
    public static final int DEFAULT_CURVE_NID = 713;

    private final ECPoint generator;
    private final BigInteger order;

    public ECCGroup() {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(DEFAULT_CURVE_NAME);
        generator = ecSpec.getG();
        order = ecSpec.getN();
    }

    /**
     * Generate a random number modulo the group order to be used as a secret.
     * @return Number modulo the group order.
     */
    public BigInteger genSecret() {
        SecureRandom secureRandom = new SecureRandom();
        BigInteger lowerBound = BigInteger.ZERO;
        BigInteger upperBound = order.subtract(BigInteger.ONE);
        return BigIntegers.createRandomInRange(lowerBound, upperBound, secureRandom);
    }

    /**
     * Get the generator element of the group.
     * @return Generator element of the group.
     */
    public ECPoint getGenerator() {
        return generator;
    }

    /**
     * Get the order of the group.
     * @return Order of the group.
     */
    public BigInteger getOrder() {
        return order;
    }

    /**
     * Raise base to the power exp.
     * @param base Base elliptic curve point.
     * @param exp Exponent to raise base to.
     * @return base to the power exp.
     */
    public ECPoint expon(ECPoint base, BigInteger exp) {
        return base.multiply(exp);
    }

    /**
     * Raise base to the power of each of the values in the exponents list.
     * @param base Base elliptic curve point.
     * @param exponents List of exponents to raise base to.
     * @return base raised to the power of each of the values in the exponents list.
     */
    public ECPoint multiexpon(ECPoint base, List<BigInteger> exponents) {
        BigInteger finalExponent = new BigInteger("1");
        for (BigInteger exponent : exponents) {
            finalExponent = finalExponent.multiply(exponent).mod(order);
        }

        return base.multiply(finalExponent);
    }

    /**
     * Convert the binary representation (unsigned) of a number into a BigInteger and take that number modulo the order of the group.
     * @param data Binary representation (unsigned) of a number.
     * @return Number modulo the group size.
     */
    public BigInteger makeexp(byte[] data) {
        // Treat data as an unsigned value
        BigInteger bigIntFromData = new BigInteger(1, data);

        return bigIntFromData.mod(this.order);
    }

    /**
     * Encode given ECPoint to a binary representation.
     * @param alpha Elliptic curve point.
     * @return Binary representation of alpha.
     */
    public byte[] printable(ECPoint alpha) {
        return alpha.getEncoded(false);
    }

}
