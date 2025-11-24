package OmniSphinx.MixFormats.PolySphinx;

public class SubHeader{
    public final byte[] nextHop;
    public final byte[] omega;
    public final byte[] alpha;
    public byte[] instructions;
    public final byte[] MAC;

    public SubHeader(byte[] nextHop, byte[] omega, byte[] alpha, byte[] instructions, byte[] MAC) {
        this.nextHop = nextHop;
        this.omega = omega;
        this.alpha = alpha;
        this.instructions = instructions;
        this.MAC = MAC;
    }

    public byte[] getNextHop() {
        return nextHop;
    }

    public byte[] getOmega() {
        return omega;
    }

    public byte[] getAlpha() {
        return alpha;
    }

    public byte[] getInstructions() {
        return instructions;
    }

    public byte[] getMAC() {
        return MAC;
    }
}
