package MasterThesisFormat.header;

import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;

import java.util.Arrays;

public final class InstructionEncryptor {
    private InstructionEncryptor() {
    }

    /**
     * Erstellt Instruction für den Header mit fixer länger!
     *  totalSize = die gewünschte End größe
     */
    public static byte[] encryptFixedSize(Params params,
                                          byte[][] instructions,
                                          byte[][] secrets,
                                          int totalSize) throws Exception {
        int hops = instructions.length;
        if (hops != secrets.length) {
            throw new IllegalArgumentException("instructions/secrets length mismatch");
        }

        int plainInstrLen = 0;
        for (byte[] instr : instructions) {
            plainInstrLen += instr.length;
        }

        int fillerLen = totalSize - plainInstrLen;

        byte[] phi = new byte[0];
        for (int i = 1; i < hops; i++) {
            int len = totalSize - (phi.length + instructions[i].length);
            byte[] tmp = new byte[len];
            System.arraycopy(phi, 0, tmp, 0, phi.length);

            byte[] prg = params.prg(params.hrho(secrets[i - 1]));
            int off = phi.length;
            byte[] slice = Arrays.copyOfRange(prg, off, off + len);
            for (int j = 0; j < len; j++) {
                tmp[j] ^= slice[j];
            }
            phi = tmp;
        }

        int instrBlockSize = totalSize - phi.length;
        byte[] instrBlock = new byte[instrBlockSize];
        int pos = 0;
        for (byte[] instr : instructions) {
            System.arraycopy(instr, 0, instrBlock, pos, instr.length);
            pos += instr.length;
        }

        byte[] onion = SerializationUtils.concatenate(instrBlock, phi);

        // encrypt recursively from last hop to first
        for (int i = hops - 1; i >= 0; i--) {
            byte[] mac = params.mu(params.hmu(secrets[i]), onion);
            byte[] enc = params.xorRho(params.hrho(secrets[i]), onion);
            onion = SerializationUtils.concatenate(mac, enc);
        }

        return onion;
    }
}