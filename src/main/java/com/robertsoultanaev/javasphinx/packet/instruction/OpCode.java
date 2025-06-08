package com.robertsoultanaev.javasphinx.packet.instruction;

public enum OpCode {
    STORE((byte) 0x00),
    STORE_BYTES((byte) 0x01),
    COMPUTE_SHARED_SECRET((byte) 0x02),
    HASH((byte) 0x03),
    MAC((byte) 0x04),
    VERIFY((byte) 0x05),
    EXPONENT((byte) 0x06),
    PAD((byte) 0x07),
    PRG_GENERATE((byte) 0x08),
    XOR((byte) 0x09),
    DECRYPT((byte) 0x0A),
    FORWARD((byte) 0x0B),
    FIND_NEXT((byte) 0x0C),    // Analysiert Beta und findet nächsten Knoten
    CONCATE((byte) 0x0D);


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