package MasterThesisFormat.header;

import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;

import java.util.Arrays;

public class InstructionDecryptor {

    /**
     * Result of a single decryption step.
     */
    public static class DecryptResult {
        private final byte[] instructions;
        private final byte[] mac;
        private final byte[] newBeta;

        public DecryptResult(byte[] instructions, byte[] mac, byte[] newBeta) {
            this.instructions = instructions;
            this.mac = mac;
            this.newBeta = newBeta;
        }

        public byte[] getInstructions() {
            return instructions.clone();
        }

        public byte[] getMac() {
            return mac.clone();
        }

        public byte[] getNewBeta() {
            return newBeta.clone();
        }
    }

    /**
     * Decrypt one instruction layer.
     * Layout for the encryptedInstructions = [ Instructions | MAC| Next Block]
     */
    public DecryptResult decrypt(Params params, byte[] encryptedInstructions, byte[] secret) throws Exception {
        if (encryptedInstructions.length != params.getInstructionTotalSize()) {
            throw new IllegalArgumentException("encryptedInstructions must match params total size");
        }

        byte[] plain = params.xorRho(params.hrho(secret), encryptedInstructions);

        int macLen = params.keyLength();
        if (plain.length < 1 + macLen) {
            throw new IllegalArgumentException("Instruction block too short");
        }

        int instrLen = Byte.toUnsignedInt(plain[0]);
        if (plain.length < 1 + instrLen + macLen) {
            throw new IllegalArgumentException("Instruction length out of bounds");
        }

        byte[] instructions = Arrays.copyOfRange(plain, 1, 1 + instrLen);
        byte[] mac = Arrays.copyOfRange(plain, 1 + instrLen, 1 + instrLen + macLen);

        // prepare zero padding and decrypt again to obtain the next layer
        int offset = 1 + instrLen + macLen;
        byte[] zeros = new byte[offset];
        Arrays.fill(zeros, (byte) 0x00);
        byte[] paddedBeta = SerializationUtils.concatenate(encryptedInstructions, zeros);
        byte[] prg = params.xorRho(params.hrho(secret), paddedBeta);
        byte[] newBeta = Arrays.copyOfRange(prg, offset, prg.length);

        if (newBeta.length != params.getInstructionTotalSize()) {
            throw new IllegalStateException("newBeta size mismatch");
        }

        return new DecryptResult(instructions, mac, newBeta);
    }
}
