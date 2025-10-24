package MasterThesisFormat.MixFormats.EROR;

import MasterThesisFormat.instruction.Instruction;
import MasterThesisFormat.instruction.InstructionRegister;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ERORInstructionPresets {
    private static final byte REG_PAYLOAD = 0x00;
    private static final byte REG_SHARED_SECRET = 0x01;
    private static final byte REG_FORWARD_PAYLOAD = 0x10;
    private static final byte REG_BACKWARD_PAYLOAD = 0x11;
    private static final byte REG_BACKWARD_CIPHER = 0x12;
    private static final byte REG_BACKWARD_MAC = 0x13;
    private static final byte REG_SALT_SKE = 0x14;
    private static final byte REG_SKE_MATERIAL = 0x15;
    private static final byte REG_K_SKE = 0x16;
    private static final byte REG_FORWARD_MAC_COMPUTED = 0x17;
    private static final byte REG_FORWARD_MAC = 0x18;
    private static final byte REG_PRF_MATERIAL = 0x19;
    private static final byte REG_K_PRF = 0x1A;
    private static final byte REG_PRF_OUTPUT = 0x1B;
    private static final byte REG_NEXT_HOP = 0x1C;

    public static byte[] createInstructions(byte[] nextHop,byte[] forwardMAC,  byte forwardPayloadLength, byte backwardCipherLength, byte backwardMacLength, byte skeSalt, byte prfSalt) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        instr.write(Instruction.storeBytes(REG_PAYLOAD, forwardPayloadLength, REG_FORWARD_PAYLOAD));
        instr.write(Instruction.storeBytes(REG_PAYLOAD, backwardCipherLength, REG_BACKWARD_CIPHER));
        instr.write(Instruction.storeBytes(REG_PAYLOAD, backwardMacLength, REG_BACKWARD_MAC));

        instr.write(Instruction.concateWithByteValue(REG_SHARED_SECRET, skeSalt, REG_SKE_MATERIAL));
        instr.write(Instruction.hash(REG_SKE_MATERIAL, REG_K_SKE));

        instr.write(Instruction.load(forwardMAC, REG_FORWARD_MAC));
        instr.write(Instruction.mac(REG_K_SKE, REG_FORWARD_PAYLOAD, REG_FORWARD_MAC_COMPUTED));
        instr.write(Instruction.verify(REG_FORWARD_MAC, REG_FORWARD_MAC_COMPUTED));

        instr.write(Instruction.decrypt(REG_K_SKE, REG_FORWARD_PAYLOAD, REG_FORWARD_PAYLOAD));
        instr.write(Instruction.decrypt(REG_K_SKE, REG_BACKWARD_CIPHER, REG_BACKWARD_CIPHER));


        instr.write(Instruction.concateWithByteValue(REG_SHARED_SECRET, prfSalt, REG_PRF_MATERIAL));
        instr.write(Instruction.hash(REG_PRF_MATERIAL, REG_K_PRF));

        instr.write(Instruction.prgGenerate(REG_K_PRF, REG_BACKWARD_CIPHER, REG_PRF_OUTPUT));
        instr.write(Instruction.xor(REG_BACKWARD_MAC, REG_PRF_OUTPUT, REG_BACKWARD_MAC));

        instr.write(Instruction.concate(REG_BACKWARD_CIPHER, REG_BACKWARD_MAC, REG_BACKWARD_PAYLOAD));
        instr.write(Instruction.concate(REG_FORWARD_PAYLOAD, REG_BACKWARD_PAYLOAD, REG_PAYLOAD));

        instr.write(Instruction.load(nextHop, REG_NEXT_HOP));
        instr.write(Instruction.forward(REG_NEXT_HOP));

        instr.write(Instruction.stop());
        return instr.toByteArray();
    }
}