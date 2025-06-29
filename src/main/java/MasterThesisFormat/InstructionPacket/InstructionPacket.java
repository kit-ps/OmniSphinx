package MasterThesisFormat.InstructionPacket;

import MasterThesisFormat.MixFormats.Packet;
import MasterThesisFormat.header.InstructionHeader;

public class InstructionPacket {
    private final InstructionHeader header;
    private final Packet packet;

    public InstructionPacket(InstructionHeader header, Packet packet) {
        this.header = header;
        this.packet = packet;
    }

    public InstructionHeader getHeader() {
        return header;
    }

    public Packet getPacket() {
        return packet;
    }
}
