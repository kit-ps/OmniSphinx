package MasterThesisFormat.header;

import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;

import java.util.Arrays;

import static MasterThesisFormat.SerializationUtils.concatenate;
import static MasterThesisFormat.SerializationUtils.slice;

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

        // Gesamtlänge aller Instruktionen
        int plainInstrLen = 0;
        for (byte[] instr : instructions) {
            plainInstrLen += instr.length;
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
}