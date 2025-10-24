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

    public static int findInstructionsEnd(byte[] plain) {
        int pc = 0;
        while (pc < plain.length) {
            int nextPc = advanceInstruction(plain, pc);
            OpCode opcode = OpCode.fromByte(plain[pc]);
            if (opcode == OpCode.STOP) {
                return nextPc;
            }
            pc = nextPc;
        }
        throw new RuntimeException("STOP instruction not found in instruction layer");
    }

    private static int advanceInstruction(byte[] buffer, int pc) {
        if (pc >= buffer.length) {
            throw new RuntimeException("Instruction parsing out of bounds");
        }

        OpCode opcode = OpCode.fromByte(buffer[pc]);
        int index = pc + 1;
        switch (opcode) {
            case STOP -> {
                return index;
            }
            case STORE_BYTES, STORE_MULTIPLE_BYTES -> {
                index = ensureAvailable(buffer, index, 3);
                return index;
            }
            case COMPUTE_SHARED_SECRET, HASH, VERIFY, FIND_NEXT -> {
                index = ensureAvailable(buffer, index, 2);
                return index;
            }
            case MAC, XOR, DECRYPT, CONCATE, CONCATE_WITH_BYTE_VALUE, ENCRYPT -> {
                index = ensureAvailable(buffer, index, 3);
                return index;
            }
            case EXPONENT -> {
                index = ensureAvailable(buffer, index, 4);
                return index;
            }
            case PAD, PRG_GENERATE -> {
                index = ensureAvailable(buffer, index, 3);
                return index;
            }
            case FORWARD -> {
                index = ensureAvailable(buffer, index, 1);
                return index;
            }
            case MIX_NONE -> {
                return index;
            }
            case MIX_TIMED, MIX_THRESHOLD, MIX_POISSON -> {
                index = ensureAvailable(buffer, index, 1);
                return index;
            }
            case MIX_POOL -> {
                index = ensureAvailable(buffer, index, 2);
                return index;
            }
            case FOR -> {
                index = ensureAvailable(buffer, index, 2);
                int instrCount = Byte.toUnsignedInt(buffer[index - 1]);
                int blockPc = index;
                for (int i = 0; i < instrCount; i++) {
                    blockPc = advanceInstruction(buffer, blockPc);
                }
                return blockPc;
            }
            case LOAD1 -> {
                return advanceLoadInstruction(buffer, index, 1);
            }
            case LOAD2 -> {
                return advanceLoadInstruction(buffer, index, 2);
            }
            case LOAD3 -> {
                return advanceLoadInstruction(buffer, index, 3);
            }
            default -> throw new RuntimeException("Unsupported opcode in instruction layer: " + opcode);
        }
    }

    private static int ensureAvailable(byte[] buffer, int index, int required) {
        if (index + required > buffer.length) {
            throw new RuntimeException("Instruction parsing exceeded buffer bounds");
        }
        return index + required;
    }

    private static int advanceLoadInstruction(byte[] buffer, int index, int lengthBytes) {
        if (index + lengthBytes > buffer.length) {
            throw new RuntimeException("LOAD instruction length prefix out of bounds");
        }

        int len = 0;
        for (int i = 0; i < lengthBytes; i++) {
            len = (len << 8) | Byte.toUnsignedInt(buffer[index++]);
        }

        if (index + len >= buffer.length) {
            throw new RuntimeException("LOAD instruction length exceeds buffer bounds");
        }

        index += len; // skip data bytes
        return index + 1; // skip destination register
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
                case CONCATE_WITH_BYTE_VALUE -> pc += 3;
                case FIND_NEXT -> pc += 2;
                case FORWARD -> pc += 2;
                default -> throw new VMException("Unknown OpCode in block: " + op);
            }
        }
        return pc;
    }
}
