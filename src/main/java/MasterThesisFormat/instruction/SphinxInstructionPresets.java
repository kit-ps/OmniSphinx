package MasterThesisFormat.instruction;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SphinxInstructionPresets {

    // Register-Definitionen
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

    public static byte[] createInstructions(byte ALPHA_LENGTH, byte BETA_LENGTH, byte KAPPA) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();



        // Paket zerlegen (danach ist jeder Teil des Packets in seinem passenden Register!)
        instr.write(Instruction.storeBytes(REG_PACKET,  ALPHA_LENGTH, REG_ALPHA));
        instr.write(Instruction.storeBytes(REG_PACKET, BETA_LENGTH, REG_BETA));
        instr.write(Instruction.storeBytes(REG_PACKET, KAPPA, REG_GAMMA)); // Gamma = KAPPA


        //Shared Secret aus Alpha berechnen
        instr.write(Instruction.computeSharedSecret(REG_ALPHA, REG_SECRET));
        instr.write(Instruction.hash( REG_SECRET, REG_SECRET));

        //MAC prüfen
        instr.write(Instruction.hash( REG_SECRET, REG_HASH_MAC));
        instr.write(Instruction.mac(REG_HASH_MAC, REG_BETA, KAPPA, REG_MAC));
        instr.write(Instruction.verify(REG_GAMMA, REG_MAC));

        //PRG erzeugen
        instr.write(Instruction.hash(REG_SECRET, REG_HASH_PRG));
        instr.write(Instruction.prgGenerate(REG_HASH_PRG, REG_PRG));

        //Beta padden und entschlüsseln
        instr.write(Instruction.pad(REG_BETA, KAPPA, REG_BETA));
        instr.write(Instruction.pad(REG_BETA, KAPPA, REG_BETA));
        instr.write(Instruction.xor(REG_BETA, REG_PRG, REG_DEC_BETA));

        //Payload entschlüsseln
        instr.write(Instruction.hash( REG_SECRET, REG_PAYLOAD));
        instr.write(Instruction.decrypt(REG_SECRET, REG_PACKET,  REG_PAYLOAD));

        //Routing-Information extrahieren
        instr.write(Instruction.findNext(REG_DEC_BETA, REG_ROUTE_INFO));

        //Extrahiere Gamma aus dem entschlüsselten Beta, in REG_DEC_BETA befindet sich nur noch Beta'
        instr.write(Instruction.storeBytes(REG_DEC_BETA,  KAPPA, REG_GAMMA));

        //Berechne das Blinding
        //instr.write(Instruction.concate(REG_ALPHA, REG_SECRET, REG_BLIND));
        instr.write(Instruction.hash(REG_SECRET, REG_BLIND));
        instr.write(Instruction.exponent(REG_ALPHA, REG_BLIND, REG_ALPHA, ALPHA_LENGTH));

        //Zusammenbauen des Headers
        instr.write(Instruction.concate(REG_ALPHA, REG_DEC_BETA, REG_ALPHA));
        instr.write(Instruction.concate(REG_ALPHA, REG_GAMMA, REG_ALPHA));

        instr.write(Instruction.concate(REG_ALPHA, REG_PAYLOAD, REG_PAYLOAD));

        //Paket an nächste Node weiterleiten
        instr.write(Instruction.forward(REG_ROUTE_INFO, REG_PAYLOAD));

        return instr.toByteArray();
    }
}
