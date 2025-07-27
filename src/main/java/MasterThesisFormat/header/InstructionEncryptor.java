package MasterThesisFormat.header;

import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import javasphinx.SphinxException;

import java.util.Arrays;

import static MasterThesisFormat.SerializationUtils.*;

public final class InstructionEncryptor {
    private InstructionEncryptor() {
    }

    /**
     * Erstellt Instruction für den Header mit fixer länger!
     *  totalSize = die gewünschte End größe
     */
    public static byte[] encryptFixedSize(Params params, byte[][] instructions, byte[][] secrets, int totalSize) throws Exception {
        int hops = instructions.length;
        if (hops != secrets.length) {
            throw new IllegalArgumentException("instructions/secrets length mismatch");
        }


        byte[] phi = {};
        int minLen = totalSize;
        for (int i = 1; i < hops; i++) {
            byte[] zeroes1 = new byte[params.keyLength() + instructions[i].length];
            Arrays.fill(zeroes1, (byte) 0x00);
            byte[] plain = SerializationUtils.concatenate(phi, zeroes1);

            byte[] zeroes2 = new byte[minLen];
            Arrays.fill(zeroes2, (byte) 0x00);
            byte[] zeroes2plain = SerializationUtils.concatenate(zeroes2, plain);

            byte[] prg = params.xorRho(params.hrho(secrets[i - 1]), zeroes2plain);
            phi = Arrays.copyOfRange(prg, minLen, prg.length);

            minLen -= instructions[i].length + params.keyLength();
            if (minLen < 0) {
                throw new IllegalArgumentException("Header too small for given instructions");
            }
        }

        byte[] Instr = params.xorRho(params.hrho(secrets[secrets.length - 1]), instructions[instructions.length - 1]); // letzte Node verschlüsseln
        Instr = concatenate(Instr, phi);
        byte[] gamma = params.mu(params.hmu(secrets[secrets.length - 1]), Instr);

        for (int i = hops - 2; i >= 0; i--) {
            byte[] currentInstr = instructions[i];
            int InstrLen = Instr.length - currentInstr.length - params.keyLength();
            byte[] plainInstr = slice(Instr, InstrLen);
            byte[] plain = concatenate(currentInstr, gamma, plainInstr);
            Instr = params.xorRho(params.hrho(secrets[i]), plain);
            gamma = params.mu(params.hmu(secrets[i]), Instr);
        }

        return Instr;
    }

    /**
     * Erstellt den Instruktionsheader, der zusätzlich zu den Instruktionen noch ein Padding besitzt um ihn auf die richtige länge zu padden
     */
    public static byte[] encryptWithPadding(Params params, byte[][] instructions, byte[][] secrets, int totalSize, byte[] padding) throws Exception {
        int hops = instructions.length;
        if (hops != secrets.length) {
            throw new IllegalArgumentException("instructions/secrets length mismatch");
        }


        byte[] phi = {};
        int minLen = totalSize;

        //Fall i = 1 direkt hier, aber mit dem Padding dazu!
        //Der erste Filler String ist so groß wie das padding + MAC + Instruktionen
        //Anstatt 0en vorne in den Filler String zu schreiben, schreibe ich das padding rein! Damit wird es mit Rho XORed.
        //Damit kann die Replication Node das Padding wieder hinzufügen und mit dem passenden Rho wieder XORed. Somit passt alles!
        byte[] zeroes1 = new byte[params.keyLength() + instructions[1].length];
        Arrays.fill(zeroes1, (byte) 0x00);
        zeroes1 = concatenate(padding, zeroes1);
        byte[] plain = SerializationUtils.concatenate(phi, zeroes1);

        byte[] zeroes2 = new byte[minLen];
        Arrays.fill(zeroes2, (byte) 0x00);
        byte[] zeroes2plain = SerializationUtils.concatenate(zeroes2, plain);

        byte[] prg = params.xorRho(params.hrho(secrets[0]), zeroes2plain);
        phi = Arrays.copyOfRange(prg, minLen, prg.length);

        minLen -= instructions[0].length + params.keyLength();
        if (minLen < 0) {
            throw new IllegalArgumentException("Header too small for given instructions");
        }


        for (int i = 2; i < hops; i++) {
            zeroes1 = new byte[params.keyLength() + instructions[i].length];
            Arrays.fill(zeroes1, (byte) 0x00);
            plain = SerializationUtils.concatenate(phi, zeroes1);

            zeroes2 = new byte[minLen];
            Arrays.fill(zeroes2, (byte) 0x00);
            zeroes2plain = SerializationUtils.concatenate(zeroes2, plain);

            prg = params.xorRho(params.hrho(secrets[i - 1]), zeroes2plain);
            phi = Arrays.copyOfRange(prg, minLen, prg.length);

            minLen -= instructions[i].length + params.keyLength();
            if (minLen < 0) {
                throw new IllegalArgumentException("Header too small for given instructions");
            }
        }

        byte[] Instr = params.xorRho(params.hrho(secrets[secrets.length - 1]), instructions[instructions.length - 1]); // letzte Node verschlüsseln
        Instr = concatenate(Instr, phi);
        byte[] gamma = params.mu(params.hmu(secrets[secrets.length - 1]), Instr);

        for (int i = hops - 2; i >= 0; i--) {
            byte[] currentInstr = instructions[i];
            int InstrLen = Instr.length - currentInstr.length - params.keyLength();
            byte[] plainInstr = slice(Instr, InstrLen);
            plain = concatenate(currentInstr, gamma, plainInstr);
            Instr = params.xorRho(params.hrho(secrets[i]), plain);
            gamma = params.mu(params.hmu(secrets[i]), Instr);
        }

        return Instr;
    }



    public static byte[] padInstructions(Params params, int padding, int currentLen, byte[] secret,
                                         int index) throws SphinxException {
        byte[] phi = {};
        byte[] zeroes1 = new byte[padding];
        Arrays.fill(zeroes1, (byte) 0x00);
        byte[] plain = SerializationUtils.concatenate(phi, zeroes1);

        byte[] zeroes2 = new byte[currentLen];
        Arrays.fill(zeroes2, (byte) 0x00);
        byte[] zeroes2plain = SerializationUtils.concatenate(zeroes2, plain);
        byte[] idx = SerializationUtils.encodeInt(index);
        secret = xorByteArrays(secret, idx);
        byte[] prg = params.xorRho(params.hrho(secret), zeroes2plain);
        phi = Arrays.copyOfRange(prg, currentLen, prg.length);
        return phi;
    }


}