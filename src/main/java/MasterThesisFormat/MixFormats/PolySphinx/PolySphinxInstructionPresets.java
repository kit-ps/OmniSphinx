package MasterThesisFormat.MixFormats.PolySphinx;

import MasterThesisFormat.instruction.Instruction;
import MasterThesisFormat.instruction.InstructionRegister;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class PolySphinxInstructionPresets {

    // === Register-Definitionen ===
    public static final byte REG_NEXT_HOP      = InstructionRegister.NEXT_HOP.getCode();
    public static final byte REG_SIGMA       = 0x20;
    public static final byte REG_PAYLOAD    = InstructionRegister.PAYLOAD.getCode();
    public static final byte REG_SEED    = 0x21;
    public static final byte REG_PATH    = 0x22;
    public static final byte REG_RECIPIENT    = 0x23;
    public static final byte REG_ROOT    = 0x24;
    public static final byte REG_P_I_J    = 0x25;
    public static final byte REG_KEYS    = 0x26;
    public static final byte REG_SUBHEADER    = 0x27;
    public static final byte REG_KEY = 0x28;
    public static final byte REG_ALPHA1 = 0x29;
    public static final byte REG_ALPHA2 = 0x2A;
    public static final byte REG_ALPHA = 0x2B;
    public static final byte REG_GAMMA = 0x2C;
    public static final byte REG_BETA = 0x2D;

    public static byte[] createRelayInstructions( byte[] nextHop, byte[] sigma) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        instr.write(Instruction.load(sigma, REG_SIGMA));
        instr.write(Instruction.encrypt(REG_SIGMA, REG_PAYLOAD, REG_PAYLOAD));
        instr.write(Instruction.load(nextHop, REG_NEXT_HOP));
        instr.write(Instruction.forward(REG_NEXT_HOP));

        instr.write(Instruction.stop());
        return instr.toByteArray();
    }

    public static byte[] createExitInstructions(byte[] seed, byte[] path, byte[] recipient, byte r, byte log2p, byte kappaLen) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        // Lade Konstanten
        instr.write(Instruction.load(seed, REG_SEED));
        instr.write(Instruction.load(path, REG_PATH));
        instr.write(Instruction.load(recipient, REG_RECIPIENT));

        // Berechne K = h(SEED) und ins Key Register laden

        instr.write(Instruction.hash(REG_SEED, REG_SIGMA));
        instr.write(Instruction.concate(REG_KEYS, REG_SIGMA, REG_KEYS));

        // Den Key Tree anhand des Paths bauen und an den Keys appenden
        // REG_SIGMA = Aktueller schlüssel
        instr.write(Instruction.forLoop(r, (byte) 5));
        instr.write(Instruction.storeBytes(REG_PATH, log2p, REG_P_I_J));  // P_i_j
        instr.write(Instruction.addRight(REG_SIGMA, REG_P_I_J, REG_SIGMA));      // K + index
        instr.write(Instruction.hash(REG_SIGMA, REG_SIGMA));                 // K = h(K)
        instr.write(Instruction.hash(REG_SIGMA, REG_SIGMA));                 //nochmal hashen für den Key
        instr.write(Instruction.concate(REG_SIGMA, REG_KEYS, REG_KEYS));


        // die Nachricht entschlüsseln
        instr.write(Instruction.forLoop( (byte) (r + 1), (byte) 2));
        instr.write(Instruction.storeBytes(REG_KEYS, kappaLen, REG_SIGMA));    // K aus Keys nehmen
        instr.write(Instruction.decrypt(REG_SIGMA, REG_PAYLOAD, REG_PAYLOAD)); // entschlüsseln

        instr.write(Instruction.forward(REG_RECIPIENT));

        instr.write(Instruction.stop());
        return instr.toByteArray();
    }

    public static byte[] createReplicationInstructions(byte kappaLen, byte twoTimesKappaLen, byte p, byte tauPost, byte[] B) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        instr.write(Instruction.load(B, REG_SUBHEADER));
        byte instrCount = 8; // so viele Instruktionen sind in der Schleife!

        //Schleife definieren
        instr.write(Instruction.forLoop(p, instrCount));

        //Schleifen-Block:
        instr.write(Instruction.storeBytes(REG_SUBHEADER, kappaLen, REG_NEXT_HOP));    // 1
        instr.write(Instruction.storeBytes(REG_SUBHEADER, kappaLen, REG_KEY));   // 2
        instr.write(Instruction.storeBytes(REG_SUBHEADER, twoTimesKappaLen, REG_ALPHA));  // 3
        instr.write(Instruction.storeBytes(REG_SUBHEADER, kappaLen, REG_GAMMA));   // 4
        instr.write(Instruction.storeBytes(REG_SUBHEADER, tauPost, REG_BETA));     // 5
        instr.write(Instruction.encrypt(REG_KEY, REG_PAYLOAD, REG_PAYLOAD));    // 6
        instr.write(Instruction.forward(REG_NEXT_HOP));                  //7

        instr.write(Instruction.stop());
        return instr.toByteArray();
    }
}
