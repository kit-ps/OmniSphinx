package OmniSphinx.header;

import org.bouncycastle.math.ec.ECPoint;

public class InstructionHeader {
    private final ECPoint alpha;
    private final byte[] instructions;
    private final byte[] MAC;


    public InstructionHeader(ECPoint alpha, byte[] instructions, byte[] MAC) {
        this.alpha = alpha;
        this.MAC = MAC;
        this.instructions = instructions.clone();
    }
    
    public byte[] getInstructions() {
        return instructions.clone();
    }

    public byte[] getMAC() {
        return MAC.clone();
    }

    public ECPoint getAlpha() {
        return alpha;
    }
}