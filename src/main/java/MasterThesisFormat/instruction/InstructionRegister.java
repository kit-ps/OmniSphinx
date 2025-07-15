package MasterThesisFormat.instruction;

public enum InstructionRegister {
    NEXT_HOP((byte) 0x00),
    NEXT_ALPHA((byte) 0x01),
    INSTRUCTIONS((byte) 0x02),
    MAC((byte) 0x03),
    PAYLOAD((byte) 0x04);

    private final byte code;

    InstructionRegister(byte code) {
        this.code = code;
    }

    public byte getCode() {
        return code;
    }
}
