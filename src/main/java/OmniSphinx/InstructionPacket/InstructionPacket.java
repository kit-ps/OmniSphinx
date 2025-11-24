package OmniSphinx.InstructionPacket;

import OmniSphinx.header.InstructionHeader;

public class InstructionPacket {
    private final InstructionHeader header;
    private final byte[] payload;

    public InstructionPacket(InstructionHeader header, byte[] payload) {
        this.header = header;
        this.payload = payload.clone();
    }

    public InstructionHeader getHeader() {
        return header;
    }

    public byte[] getPayload() {
        return payload.clone();
    }
}
