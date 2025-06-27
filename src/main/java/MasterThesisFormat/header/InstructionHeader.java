package MasterThesisFormat.header;

import MasterThesisFormat.MixFormats.Packet;
import org.bouncycastle.math.ec.ECPoint;

public class InstructionHeader {
    private final ECPoint alpha;
    private final byte[] MAC;
    private final byte[] instructions;
    private final Packet packet;


    public InstructionHeader(ECPoint alpha, byte[] MAC, byte[] instructions, Packet packet) {
        this.alpha = alpha;
        this.MAC = MAC;
        this.instructions = instructions.clone();
        this.packet = packet;
    }
    
    public byte[] getInstructions() {
        return instructions.clone();
    }

    public byte[] getMAC() {
        return MAC;
    }

    public ECPoint getAlpha() {
        return alpha;
    }

    public Packet getPacket() {
        return packet;
    }
}