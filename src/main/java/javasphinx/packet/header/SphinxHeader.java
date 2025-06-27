package javasphinx.packet.header;

import MasterThesisFormat.MixFormats.Header;
import org.bouncycastle.math.ec.ECPoint;

public class SphinxHeader extends Header {
    private final ECPoint alpha;
    private final byte[] beta;
    private final byte[] gamma;


    public SphinxHeader (ECPoint alpha, byte[] beta, byte[] gamma){
        if (alpha == null) throw new IllegalArgumentException("alpha cannot be null");
        if (beta == null) throw new IllegalArgumentException("beta cannot be null");
        if (gamma == null) throw new IllegalArgumentException("gamma cannot be null");

        this.alpha = alpha;
        // Defensive Kopien
        this.beta = beta.clone();
        this.gamma = gamma.clone();

    }

    public ECPoint getAlpha() {
        return alpha;
    }
    public byte[] getBeta() {
        return beta.clone();
    }
    
    public byte[] getGamma() {
        return gamma.clone();
    }

}