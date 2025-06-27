package MasterThesisFormat;


import javasphinx.crypto.ECCGroup;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class Params {
    private final int keyLength;
    private final int bodyLength;
    private final int headerLength;
    private final ECCGroup group;

    public Params(int keyLength, int bodyLength, int headerLength, ECCGroup group) {
        this.keyLength = keyLength;
        this.bodyLength = bodyLength;
        this.headerLength = headerLength;
        this.group = group;
    }

    public Params() {
        this(16, 1024, 192, new ECCGroup());
    }

    public int keyLength() {
        return keyLength;
    }

    public int bodyLength() {
        return bodyLength;
    }

    public int headerLength() {
        return headerLength;
    }

    public int packetLength() {
        return headerLength + bodyLength;
    }

    public ECCGroup getGroup() {
        return group;
    }

    public BigInteger generatePrivateKey() {
        return group.genSecret();
    }

    public ECPoint derivePublicKey(BigInteger privateKey) {
        return group.expon(group.getGenerator(), privateKey);
    }


}
