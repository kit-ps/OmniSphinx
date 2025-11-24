package OmniSphinx.instruction;

public enum OpCode {
    STOP((byte) 0x00),
    STORE_BYTES1((byte) 0x01),
    HASH((byte) 0x03),
    MAC((byte) 0x04),
    VERIFY((byte) 0x05),
    EXPONENT((byte) 0x06),
    PAD((byte) 0x07),
    PRG_GENERATE((byte) 0x08),
    XOR((byte) 0x09),
    DECRYPT((byte) 0x0A),
    FORWARD((byte) 0x0B),
    CONCATE((byte) 0x0D),
    COPY((byte) 0x0E),
    ENCRYPT((byte) 0x0F),
    MIX_NONE((byte) 0x10),
    MIX_TIMED((byte) 0x11),
    MIX_THRESHOLD((byte) 0x12),
    MIX_POOL((byte) 0x13),
    MIX_POISSON((byte) 0x14),
    STORE_BYTES2((byte) 0x15),
    ADD((byte) 0x16),
    CONCATE_WITH_BYTE_VALUE((byte)0x18),
    FOR((byte) 0x19),
    STORE_MULTIPLE_BYTES((byte)0x1A),
    LOAD_MULTIPLE_BYTES((byte)0x1B),
    LOAD1((byte) 0x1C),
    LOAD2((byte) 0x1D),
    LOAD3((byte) 0x1E),
    STORE_BYTES3((byte) 0x1F),
    STORE_BYTES4((byte) 0x20);

    private final byte code;
    
    OpCode(byte code) {
        this.code = code;
    }
    
    public byte getCode() {
        return code;
    }

    public static OpCode fromByte(byte code) {
        for (OpCode opCode : values()) {
            if (opCode.code == code) {
                return opCode;
            }
        }
        throw new IllegalArgumentException("Unknown opcode: " + code);
    }
}
