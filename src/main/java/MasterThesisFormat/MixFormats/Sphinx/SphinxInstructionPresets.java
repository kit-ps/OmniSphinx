package MasterThesisFormat.MixFormats.Sphinx;

import MasterThesisFormat.instruction.Instruction;
import MasterThesisFormat.instruction.InstructionRegister;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SphinxInstructionPresets {

    // Register-Definitionen
    private static final byte REG_PAYLOAD = InstructionRegister.PAYLOAD.getCode();
    private static final byte REG_SHARED_SECRET = InstructionRegister.NEXT_ALPHA.getCode();
    private static final byte REG_HASH_PAYLOAD = (byte) 0x20;
    private static final byte REG_NEXT_HOP = (byte) 0x21;

    public static byte[] createInstructions(byte[] nextHop, byte salt) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        //Payload entschlüsseln
        instr.write(Instruction.concateWithByteValue(REG_SHARED_SECRET, salt, REG_SHARED_SECRET));
        instr.write(Instruction.hash(REG_SHARED_SECRET, REG_HASH_PAYLOAD));
        instr.write(Instruction.decrypt(REG_HASH_PAYLOAD, REG_PAYLOAD,  REG_PAYLOAD));

        //Mixen

        instr.write(Instruction.load(nextHop, REG_NEXT_HOP));
        instr.write(Instruction.forward(REG_NEXT_HOP));

        byte[] raw = instr.toByteArray();
        if (raw.length > 255) {
            throw new IOException("Instruction block too large");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((byte) raw.length);
        out.write(raw);
        return out.toByteArray();
    }
}
