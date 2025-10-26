package MasterThesisFormat.header;

import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import MasterThesisFormat.OmniSphinxException;

import java.util.Arrays;

import static MasterThesisFormat.SerializationUtils.*;

public final class InstructionEncryptor {
    private InstructionEncryptor() {
    }

    /**
     * Erstellt Instruction für den Header mit fixer länger!
     *  totalSize = die gewünschte End größe
     *  Instructions sind schon gepaddet und sind insgesamt der Größe totalSize
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

            phi = params.xorRho(params.hrho(secrets[i - 1]), zeroes2plain);

            phi = slice(phi, minLen, phi.length);


            if (minLen < 0) {
                throw new IllegalArgumentException("Header too small for given instructions");
            }

            minLen = minLen - instructions[i].length - params.keyLength();
        }

        byte[] beta = instructions[instructions.length - 1];
        beta = params.xorRho(params.hrho(secrets[secrets.length - 1]), beta);
        beta = concatenate(beta, phi);
        beta = slice(beta, totalSize);

        byte[] gamma = params.mac(params.hmu(secrets[secrets.length - 1]), beta);
        for (int i = hops - 2; i >= 0; i--) {
            byte[] currentInstr = instructions[i];
            byte[] plain = concatenate(currentInstr, gamma, beta);
            plain = slice(plain, totalSize);
            beta = params.xorRho(params.hrho(secrets[i]), plain);
            gamma = params.mac(params.hmu(secrets[i]), beta);
        }

        return beta;
    }

    /**
     * Erstellt den Instruktionsheader, der zusätzlich zu den Instruktionen noch ein Padding besitzt um ihn auf die richtige länge zu padden
     * Das heißt hier sind die Instructionen nicht auf die richtige länge gepaddet
     */
    public static byte[] encryptWithPadding(Params params, byte[][] instructions, byte[][] secrets, int totalSize, byte[] padding) throws Exception {
        int hops = instructions.length;
        if (hops != secrets.length) {
            throw new IllegalArgumentException("instructions/secrets length mismatch");
        }


        byte[] phi = padding;
        int minLen = totalSize - padding.length;

        for (int i = 1; i < hops; i++) {
            byte[] zeroes1 = new byte[params.keyLength() + instructions[i].length];
            Arrays.fill(zeroes1, (byte) 0x00);
            byte[] plain = SerializationUtils.concatenate(phi, zeroes1);

            byte[] zeroes2 = new byte[minLen];
            Arrays.fill(zeroes2, (byte) 0x00);
            byte[] zeroes2plain = SerializationUtils.concatenate(zeroes2, plain);

            phi = params.xorRho(params.hrho(secrets[i - 1]), zeroes2plain);

            phi = slice(phi, minLen, phi.length);


            if (minLen < 0) {
                throw new IllegalArgumentException("Header too small for given instructions");
            }

            minLen = minLen - instructions[i].length - params.keyLength();
        }

        byte[] beta = instructions[instructions.length - 1];
        beta = params.xorRho(params.hrho(secrets[secrets.length - 1]), beta);
        beta = concatenate(beta, phi);
        beta = slice(beta, totalSize);

        byte[] gamma = params.mac(params.hmu(secrets[secrets.length - 1]), beta);
        for (int i = hops - 2; i >= 0; i--) {
            byte[] currentInstr = instructions[i];
            byte[] plain = concatenate(currentInstr, gamma, beta);
            plain = slice(plain, totalSize);
            beta = params.xorRho(params.hrho(secrets[i]), plain);
            gamma = params.mac(params.hmu(secrets[i]), beta);
        }

        return beta;
    }

    public static byte[] padInstructions(Params params, int padding, int currentLen, byte[] secret,
                                         int index) throws OmniSphinxException {
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