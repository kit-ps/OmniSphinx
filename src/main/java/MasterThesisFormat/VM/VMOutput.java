package MasterThesisFormat.VM;

public class VMOutput {
    private final byte[] nextHop;
    private final byte[] nextAlpha;
    private final byte[] instructions;
    private final byte[] MAC;
    private final byte[] outgoingPayload;

    public VMOutput(byte[] nextHop, byte[] nextAlpha, byte[] instructions, byte[] MAC, byte[] outgoingPayload) {
        this.nextHop = nextHop;
        this.nextAlpha = nextAlpha;
        this.instructions = instructions;
        this.MAC = MAC;
        this.outgoingPayload = outgoingPayload;
    }

    public byte[] getNextHop() {
        return nextHop.clone();
    }

    public byte[] getMAC() {
        return MAC;
    }

    public byte[] getNextAlpha() {
        return nextAlpha;
    }

    public byte[] getInstructions() {
        return instructions;
    }

    public byte[] getOutgoingPayload() {
        return outgoingPayload.clone();
    }
}