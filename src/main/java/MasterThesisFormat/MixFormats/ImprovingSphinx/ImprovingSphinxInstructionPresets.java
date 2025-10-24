package MasterThesisFormat.MixFormats.ImprovingSphinx;

import MasterThesisFormat.instruction.Instruction;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ImprovingSphinxInstructionPresets {
    private static final byte REG_PAYLOAD = 0x00;
    private static final byte REG_SHARED_SECRET = 0x01;
    private static final byte REG_HASH_PAYLOAD = 0x03;
    private static final byte REG_SHARED_SECRET_PAYLOAD = 0x05;
    private static final byte REG_SHARED_SECRET_MAC = 0x06;
    private static final byte REG_PAYLOAD_MAC = 0x07;
    private static final byte REG_MAC = 0x08;
    private static final byte REG_MAC_MATERIAL = 0x15;
    private static final byte REG_NEXT_HOP = 0x1C;

    public static byte[] createInstructions(byte[] nextHop, byte salt, byte[] MAC, byte saltMAC) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        instr.write(Instruction.load(MAC, REG_MAC));
        instr.write(Instruction.concateWithByteValue(REG_SHARED_SECRET, saltMAC, REG_SHARED_SECRET_MAC));
        instr.write(Instruction.hash(REG_SHARED_SECRET_MAC, REG_MAC_MATERIAL));
        instr.write(Instruction.mac(REG_MAC_MATERIAL, REG_PAYLOAD, REG_PAYLOAD_MAC));
        instr.write(Instruction.verify(REG_MAC, REG_PAYLOAD_MAC));

        //Payload entschlüsseln
        instr.write(Instruction.concateWithByteValue(REG_SHARED_SECRET, salt, REG_SHARED_SECRET_PAYLOAD));
        instr.write(Instruction.hash(REG_SHARED_SECRET_PAYLOAD, REG_HASH_PAYLOAD));
        instr.write(Instruction.decrypt(REG_HASH_PAYLOAD, REG_PAYLOAD,  REG_PAYLOAD));


        //Mixen

        instr.write(Instruction.load(nextHop, REG_NEXT_HOP));
        instr.write(Instruction.forward(REG_NEXT_HOP));

        instr.write(Instruction.stop());
        return instr.toByteArray();
    }
}
