package OmniSphinx.InstructionPacket;

/**
 *  holder for an outgoing instruction packet and its next hop address.
 */
public class InstructionPacketAndNextHop {
    private final byte[] nextHop;
    private final InstructionPacket packet;

    public InstructionPacketAndNextHop(byte[] nextHop, InstructionPacket packet) {
        this.nextHop = nextHop;
        this.packet = packet;
    }

    public byte[] getNextHop() {
        return nextHop;
    }

    public InstructionPacket getPacket() {
        return packet;
    }
}