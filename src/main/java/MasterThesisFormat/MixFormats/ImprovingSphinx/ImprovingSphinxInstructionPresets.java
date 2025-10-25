package MasterThesisFormat.MixFormats.ImprovingSphinx;

import MasterThesisFormat.instruction.Instruction;
import MasterThesisFormat.instruction.InstructionRegister;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ImprovingSphinxInstructionPresets {
    private static final byte REG_PAYLOAD = InstructionRegister.PAYLOAD.getCode();
    private static final byte REG_SHARED_SECRET = InstructionRegister.SHARED_SECRET.getCode();
    private static final byte REG_HASH_PAYLOAD = 0x20;
    private static final byte REG_SHARED_SECRET_PAYLOAD = 0x21;
    private static final byte REG_SHARED_SECRET_MAC = 0x22;
    private static final byte REG_PAYLOAD_MAC = 0x23;
    private static final byte REG_MAC = InstructionRegister.MAC.getCode();
    private static final byte REG_MAC_MATERIAL = 0x24;
    private static final byte REG_NEXT_HOP = InstructionRegister.NEXT_HOP.getCode();

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
