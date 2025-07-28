package MasterThesisFormat.MixFormats.PolySphinx;

public class SubHeader{
    public final byte[] nextHop;
    public final byte[] omega;
    public final byte[] alpha;
    public final byte[] instructions;
    public final byte[] MAC;

    public SubHeader(byte[] nextHop, byte[] omega, byte[] alpha, byte[] instructions, byte[] MAC) {
        this.nextHop = nextHop;
        this.omega = omega;
        this.alpha = alpha;
        this.instructions = instructions;
        this.MAC = MAC;
    }
}
