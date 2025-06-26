package MasterThesisFormat.instruction;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class MultiSphinxInstructionPresets {
    private static final byte REG_PACKET     = 0x00;
    private static final byte REG_ALPHA      = 0x04;
    private static final byte REG_BETA       = 0x05;
    private static final byte REG_GAMMA      = 0x06;
    private static final byte REG_SECRET     = 0x07;
    private static final byte REG_HASH_MAC   = 0x08;
    private static final byte REG_MAC        = 0x09;
    private static final byte REG_HASH_PRG   = 0x0A;
    private static final byte REG_PRG        = 0x0B;
    private static final byte REG_BETA_PAD   = 0x0C;
    private static final byte REG_DEC_BETA   = 0x0D;
    private static final byte REG_PAYLOAD    = 0x0E;
    private static final byte REG_ROUTE_INFO = 0x0F;
    private static final byte REG_BLIND      = 0x10;
    private static final byte REG_HEADER      = 0x11;
    private static final byte REG_HASH_PAYLOAD      = 0x12;
    private static final byte REG_NEXT_BETA    = 0x13;
    private static final byte REG_NEXT_GAMMA     = 0x14;

    public static byte[] Process(byte alphaLen, byte betaLen, byte kappaLen) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        // Extract input packet structure: [Alpha | Beta | Gamma | Payload]
        instr.write(Instruction.storeBytes(REG_PACKET, alphaLen, REG_ALPHA));
        instr.write(Instruction.storeBytes(REG_PACKET, betaLen, REG_BETA));
        instr.write(Instruction.storeBytes(REG_PACKET, kappaLen, REG_GAMMA));

        // Concatenate Beta with Payload for MAC
        instr.write(Instruction.concate(REG_PACKET, REG_BETA, REG_HEADER));

        // Compute shared secret s_i = DH(alpha_i, y_i)
        instr.write(Instruction.computeSharedSecret(REG_ALPHA, REG_SECRET));

        // Verify MAC
        instr.write(Instruction.hash(REG_SECRET, REG_HASH_MAC));
        instr.write(Instruction.mac(REG_HASH_MAC, REG_HEADER, kappaLen, REG_MAC));
        instr.write(Instruction.verify(REG_GAMMA, REG_MAC));

        //Payload entschlüsseln
        instr.write(Instruction.hash( REG_SECRET, REG_HASH_PAYLOAD));
        instr.write(Instruction.decrypt(REG_HASH_PAYLOAD, REG_PACKET,  REG_PAYLOAD));

        // Generate PRG stream and decrypt Beta
        instr.write(Instruction.hash(REG_SECRET, REG_HASH_PRG));
        instr.write(Instruction.prgGenerate(REG_HASH_PRG, REG_PRG));
        instr.write(Instruction.xor(REG_HEADER, REG_PRG, REG_DEC_BETA));

        // Extract fields for next hop
        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_NEXT_BETA));
        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_NEXT_GAMMA));

        // Blinding update for Alpha
        instr.write(Instruction.hash(REG_SECRET, REG_BLIND));
        instr.write(Instruction.exponent(REG_ALPHA, REG_BLIND, REG_ALPHA, alphaLen));

        // Rebuild packet
        instr.write(Instruction.concate(REG_ALPHA, REG_NEXT_BETA, REG_ALPHA));
        instr.write(Instruction.concate(REG_ALPHA, REG_NEXT_GAMMA, REG_ALPHA));
        instr.write(Instruction.concate(REG_ALPHA, REG_PAYLOAD, REG_PAYLOAD));

        // Forward packet
        instr.write(Instruction.forward(REG_ROUTE_INFO, REG_PAYLOAD));

        return instr.toByteArray();
    }
}
