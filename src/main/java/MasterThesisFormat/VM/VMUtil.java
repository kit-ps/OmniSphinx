package MasterThesisFormat.VM;

import MasterThesisFormat.instruction.OpCode;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public final class VMUtil {

    public static byte[] aesCtrKeystream(byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] zeroInput = new byte[1024]; // enthält nur 0x00
        return aesCtr(key, zeroInput, iv);   // nutzt deine bestehende aesCtr
    }

    public static byte[] aesCtr(byte[] key, byte[] message, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(message);
    }

    public static byte[] slice(byte[] source, int start, int end) {
        int resultLength = end - start;
        byte[] result = new byte[resultLength];
        System.arraycopy(source, start, result, 0, resultLength);
        return result;
    }

    public static byte[] slice(byte[] source, int end) {
        return slice(source, 0, end);
    }



    public static byte[] concatenate(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }

        byte[] result = new byte[length];

        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }

        return result;
    }

    public static int calculateBlockEnd(byte[] instructions, int programCounter, int instrCount) throws VMException {
        int pc = programCounter;
        for (int i = 0; i < instrCount; i++) {
            OpCode op = OpCode.fromByte(instructions[pc++]); // opcode selbst

            switch (op) {
                case STORE_BYTES -> pc += 3; // 3 args: source, length, destReg
                case COMPUTE_SHARED_SECRET -> pc += 2;
                case HASH -> pc += 2;
                case MAC -> pc += 3;
                case VERIFY -> pc += 2;
                case EXPONENT -> pc += 4;
                case PAD -> pc += 3;
                case PRG_GENERATE -> pc += 3;
                case XOR -> pc += 3;
                case DECRYPT -> pc += 3;
                case CONCATE -> pc += 3;
                case FIND_NEXT -> pc += 2;
                case FORWARD -> pc += 2;
                default -> throw new VMException("Unknown OpCode in block: " + op);
            }
        }
        return pc;
    }
}
