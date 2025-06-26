package MasterThesisFormat.instruction;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class PolySphinxInstructionPresets {

    // === Register-Definitionen ===
    public static final byte REG_PACKET     = 0x00;
    public static final byte REG_ALPHA      = 0x04;
    public static final byte REG_BETA       = 0x05;
    public static final byte REG_GAMMA      = 0x06;
    public static final byte REG_SECRET     = 0x07;
    public static final byte REG_HASH_MAC   = 0x08;
    public static final byte REG_MAC        = 0x09;
    public static final byte REG_HASH_PRG   = 0x0A;
    public static final byte REG_PRG        = 0x0B;
    public static final byte REG_BETA_PAD   = 0x0C;
    public static final byte REG_DEC_BETA   = 0x0D;
    public static final byte REG_PAYLOAD    = 0x0E;
    public static final byte REG_ROUTE_INFO = 0x0F;
    public static final byte REG_BLIND      = 0x10;
    public static final byte REG_FLAG       = 0x11;
    public static final byte REG_OMEGA      = 0x12;
    public static final byte REG_PATH       = 0x13;
    public static final byte REG_SEED       = 0x13;
    public static final byte REG_ALPHA1     = 0x14;
    public static final byte REG_ALPHA2     = 0x15;
    public static final byte REG_KEYS       = 0x16;


    public static byte[] createPolySphinxInstructions(byte alphaLen, byte betaLen, byte kappaLen, byte flag, byte pathLen, byte r, byte logP, byte p, byte tauPost) throws IOException {

        ByteArrayOutputStream instr = new ByteArrayOutputStream();


        // Paket zerlegen
        instr.write(Instruction.storeBytes(REG_PACKET, alphaLen, REG_ALPHA));
        instr.write(Instruction.storeBytes(REG_PACKET, betaLen ,REG_BETA));
        instr.write(Instruction.storeBytes(REG_PACKET, kappaLen, REG_GAMMA));

        // 3. Shared Secret berechnen
        instr.write(Instruction.computeSharedSecret(REG_ALPHA, REG_SECRET));

        // 4. MAC prüfen (HMAC-SHA256)
        instr.write(Instruction.hash(REG_SECRET, REG_HASH_MAC));
        instr.write(Instruction.mac(REG_HASH_MAC, REG_BETA, kappaLen, REG_MAC));
        instr.write(Instruction.verify(REG_GAMMA, REG_MAC));

        // 5. PRG generieren
        instr.write(Instruction.hash(REG_SECRET, REG_HASH_PRG));
        instr.write(Instruction.prgGenerate(REG_HASH_PRG,  REG_PRG));

        // 6. Beta paddieren & entschlüsseln
        //TODO: MUSS hier 1 oder 8 stehen?! Also arbeite ich mit bytes oder bits?!
        instr.write(Instruction.pad(REG_BETA, (byte) 1, REG_BETA_PAD));
        instr.write(Instruction.pad(REG_BETA, kappaLen, REG_BETA_PAD));
        instr.write(Instruction.pad(REG_BETA, kappaLen, REG_BETA_PAD));
        instr.write(Instruction.xor(REG_BETA_PAD, REG_PRG, REG_DEC_BETA));

        // Braucht man nicht, jedoch will ich die ersten 8 Bits halt weg machen!
        instr.write(Instruction.storeBytes(REG_DEC_BETA, (byte) 1, REG_FLAG));

        switch(flag) {
            case 0x00 -> {
                instr.write(createRelayInstructions(alphaLen, kappaLen));
            }
            case 0x01 -> {
                instr.write(createExitInstructions(kappaLen, pathLen, r, logP));
            }
            case 0x02 -> {
                instr.write(createReplicationInstructions(kappaLen, p, tauPost));
            }
            default -> throw new IllegalArgumentException("Unknown Flag: " + flag);
        }

        return instr.toByteArray();
    }

    private static byte[] createRelayInstructions(byte alphaLen, byte kappaLen) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        instr.write(Instruction.storeBytes(REG_DEC_BETA, (byte) 1, REG_ROUTE_INFO));

        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_GAMMA));

        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_OMEGA));

        //Berechne das Blinding
        //instr.write(Instruction.concate(REG_ALPHA, REG_SECRET, REG_BLIND));
        instr.write(Instruction.hash(REG_SECRET, REG_BLIND));
        instr.write(Instruction.exponent(REG_ALPHA, REG_BLIND, REG_ALPHA, alphaLen));


        instr.write(Instruction.encrypt(REG_OMEGA, REG_PACKET, REG_PAYLOAD));

        //Zusammenbauen des Headers
        instr.write(Instruction.concate(REG_ALPHA, REG_DEC_BETA, REG_ALPHA));
        instr.write(Instruction.concate(REG_ALPHA, REG_GAMMA, REG_ALPHA));
        instr.write(Instruction.concate(REG_ALPHA, REG_PAYLOAD, REG_PAYLOAD));

        //Paket an nächste Node weiterleiten
        instr.write(Instruction.forward(REG_ROUTE_INFO, REG_PAYLOAD));
        return instr.toByteArray();
    }


    private static byte[] createReplicationInstructions(byte kappaLen, byte p, byte tauPost) throws IOException {

        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        byte instrCount = 12; // so viele Instruktionen sind in der Schleife!
        //Schleife definieren
        instr.write(Instruction.forLoop(p, instrCount));


        // === Schleifen-Block: definieren ===

        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_PATH));    // 1
        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_OMEGA));   // 2
        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_ALPHA1));  // 3
        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_ALPHA2));  // 4
        instr.write(Instruction.concate(REG_ALPHA1, REG_ALPHA2, REG_ALPHA));      // 5
        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_GAMMA));   // 6
        instr.write(Instruction.storeBytes(REG_DEC_BETA, tauPost, REG_BETA));     // 7
        instr.write(Instruction.encrypt(REG_OMEGA, REG_PAYLOAD, REG_PAYLOAD));    // 8
        instr.write(Instruction.concate(REG_ALPHA, REG_BETA, REG_ALPHA));         // 9
        instr.write(Instruction.concate(REG_ALPHA, REG_GAMMA, REG_ALPHA));        //10
        instr.write(Instruction.concate(REG_ALPHA, REG_PAYLOAD, REG_PAYLOAD));    //11
        instr.write(Instruction.forward(REG_PATH, REG_PAYLOAD));                  //12

        return instr.toByteArray();
    }

    private static byte[] createExitInstructions(byte kappaLen, byte pathLen, byte r, byte logP) throws IOException {

        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        // 1) Seed, Path, Empfänger
        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_SEED));
        instr.write(Instruction.storeBytes(REG_DEC_BETA, pathLen, REG_PATH));
        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_ROUTE_INFO));

        // 2) K0 = h(SEED)
        instr.write(Instruction.hash(REG_SEED, REG_OMEGA));
        instr.write(Instruction.concate(REG_KEYS, REG_OMEGA, REG_KEYS)); // append K0

        byte instrCount = 4;
        instr.write(Instruction.forLoop( r, instrCount));

        // 3) FOR: build Key Tree & append each K

        instr.write(Instruction.storeBytes(REG_PATH, logP, REG_BLIND));         // get index
        instr.write(Instruction.concate(REG_OMEGA, REG_BLIND, REG_OMEGA));      // K + index
        instr.write(Instruction.hash(REG_OMEGA, REG_OMEGA));                    // K'
        instr.write(Instruction.concate(REG_OMEGA, REG_KEYS, REG_KEYS));        // append K'


        instrCount = 2;
        instr.write(Instruction.forLoop( (byte) (r+1), instrCount));

        // 4) FOR: peel backwards
        instr.write(Instruction.storeBytes(REG_KEYS, kappaLen, REG_OMEGA));    // extract K
        instr.write(Instruction.decrypt(REG_OMEGA, REG_PAYLOAD, REG_PAYLOAD)); // decrypt


        // 5) Forward Klartext
        instr.write(Instruction.forward(REG_ROUTE_INFO, REG_PAYLOAD));

        return instr.toByteArray();
    }



    private static byte[] createReplicationInstructionsOld(byte kappaLen, byte p, byte tauPost) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        for (byte i = 0; i < p; i++) {

            // Extrahiere Subheader i
            // Next Hop = erste kappa Bits im Subheader
            instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_PATH));

            // Key = nächste kappa Bits
            instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_OMEGA));

            //ALPHA
            instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_ALPHA1));
            instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_ALPHA2));
            instr.write(Instruction.concate(REG_ALPHA1, REG_ALPHA2, REG_ALPHA));

            //  Gamma = nächste kappa Bits
            instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_GAMMA));

            instr.write(Instruction.storeBytes(REG_DEC_BETA, tauPost, REG_BETA));

            // Payload neu verschlüsseln
            instr.write(Instruction.encrypt(REG_OMEGA, REG_PAYLOAD, REG_PAYLOAD));

            // Header bauen: [Alpha | Beta | Gamma | PayLoad]
            instr.write(Instruction.concate(REG_ALPHA, REG_BETA, REG_ALPHA));
            instr.write(Instruction.concate(REG_ALPHA, REG_GAMMA, REG_ALPHA));
            instr.write(Instruction.concate(REG_ALPHA, REG_PAYLOAD, REG_PAYLOAD));

            // Packet weiterleiten an Next Hop
            instr.write(Instruction.forward(REG_PATH, REG_PAYLOAD));
        }

        return instr.toByteArray();
    }


    private static byte[] createExitInstructionsOld(byte kappaLen, byte pathLen, byte r, byte logP) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        // SEED für den key tree
        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_SEED));

        // Path P_i
        instr.write(Instruction.storeBytes(REG_DEC_BETA, pathLen, REG_PATH));

        // recipient address
        instr.write(Instruction.storeBytes(REG_DEC_BETA, kappaLen, REG_ROUTE_INFO));

        // Starten mit Root (K = hK(SEED))
        instr.write(Instruction.hash(REG_SEED, REG_OMEGA));

        // Für jede Ebene im Baum:
        for (int j = 0; j < r; j++) {

            // Extrahiere den nächsten Index aus PATH P_i
            instr.write(Instruction.storeBytes(REG_PATH, logP, REG_BLIND));

            // K = hK(K ++ index)
            instr.write(Instruction.concate(REG_OMEGA, REG_BLIND, REG_OMEGA));
            instr.write(Instruction.hash(REG_OMEGA, REG_OMEGA));

            // Entschlüssele Payload mit K
            instr.write(Instruction.decrypt(REG_OMEGA, REG_PAYLOAD, REG_PAYLOAD));
        }

        // Ist jetzt REG_PAYLOAD im Klartext? Oder muss ich nochmal mit K[] entschlüsseln?
        instr.write(Instruction.forward(REG_ROUTE_INFO, REG_PAYLOAD));
        return instr.toByteArray();
    }
}
