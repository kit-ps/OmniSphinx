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

        //Pad Instruktionen auf totalSize - phi.length
        int instrBlockSize = totalSize - phi.length;
        byte[] instrBlock = new byte[instrBlockSize];
        int pos = 0;
        for (byte[] instr : instructions) {
            System.arraycopy(instr, 0, instrBlock, pos, instr.length);
            pos += instr.length;
        }

        byte[] onion = SerializationUtils.concatenate(instrBlock, phi);

        // Verschlüsselung
        for (int i = hops - 1; i >= 0; i--) {
            byte[] mac = params.mu(params.hmu(secrets[i]), onion);
            byte[] enc = params.xorRho(params.hrho(secrets[i]), onion);
            onion = SerializationUtils.concatenate(mac, enc);
        }

        return onion;
    }
}