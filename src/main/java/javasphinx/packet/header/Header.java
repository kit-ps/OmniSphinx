package javasphinx.packet.header;

import org.bouncycastle.math.ec.ECPoint;

public record Header(
        ECPoint alpha,
        byte[] beta,
        byte[] gamma


) {
    public Header {
        if (alpha == null) throw new IllegalArgumentException("alpha cannot be null");
        if (beta == null) throw new IllegalArgumentException("beta cannot be null");
        if (gamma == null) throw new IllegalArgumentException("gamma cannot be null");

        // Defensive Kopien
        beta = beta.clone();
        gamma = gamma.clone();

    }
    
    public byte[] getBeta() {
        return beta.clone();
    }
    
    public byte[] getGamma() {
        return gamma.clone();
    }

}