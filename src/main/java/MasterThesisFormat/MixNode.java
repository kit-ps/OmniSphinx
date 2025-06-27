package MasterThesisFormat;

import MasterThesisFormat.MixFormats.Packet;

import java.math.BigInteger;

public class MixNode {
    private final BigInteger secret;
    private final Params params;

    public MixNode(BigInteger secret, Params params) {
        this.secret = secret;
        this.params = params;
    }

    public Packet process(Packet packet) {
        return null;
    }
}
