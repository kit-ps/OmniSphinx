package OmniSphinx.instruction;


import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Instruction {

    public static byte[] storeBytes(byte source, int length, byte destReg) {
        if (length < 0) {
            throw new IllegalArgumentException("Length must be non-negative");
        }

        if (length <= 0xFF) {
            return new byte[]{OpCode.STORE_BYTES1.getCode(), source, (byte) length, destReg};
        } else if (length <= 0xFFFF) {
            return new byte[]{OpCode.STORE_BYTES2.getCode(), source,
                    (byte) ((length >> 8) & 0xFF),
                    (byte) (length & 0xFF),
                    destReg};
        } else if (length <= 0xFFFFFF) {
            return new byte[]{OpCode.STORE_BYTES3.getCode(), source,
                    (byte) ((length >> 16) & 0xFF),
                    (byte) ((length >> 8) & 0xFF),
                    (byte) (length & 0xFF),
                    destReg};
        } else {
            return new byte[]{OpCode.STORE_BYTES4.getCode(), source,
                    (byte) ((length >> 24) & 0xFF),
                    (byte) ((length >> 16) & 0xFF),
                    (byte) ((length >> 8) & 0xFF),
                    (byte) (length & 0xFF),
                    destReg};
        }
    }

    public static byte[] storeMultipleBytes(byte source,  byte lengthReg, byte destReg) {
        return new byte[]{OpCode.STORE_MULTIPLE_BYTES.getCode(), source,  lengthReg, destReg};
    }

    public static byte[] hash(byte inputReg, byte destReg) {
        return new byte[]{OpCode.HASH.getCode(), inputReg,  destReg};
    }

    public static byte[] copy(byte sourceReg, byte destReg) {
        return new byte[]{OpCode.COPY.getCode(), sourceReg, destReg};
    }

    public static byte[] mac(byte keyReg, byte dataReg, byte destReg) {
        return new byte[]{OpCode.MAC.getCode(), keyReg, dataReg, destReg};
    }

    public static byte[] stop() {
        return new byte[]{OpCode.STOP.getCode()};
    }

    public static byte[] verify(byte expectedReg, byte computedReg) {
        return new byte[]{OpCode.VERIFY.getCode(), expectedReg, computedReg};
    }

    public static byte[] exponent(byte inputReg1, byte inputReg2, byte destReg,  byte outputlength) {
        return new byte[]{OpCode.EXPONENT.getCode(), inputReg1, inputReg2, destReg, outputlength};
    }

    public static byte[] pad(byte inputReg, byte Length, byte destReg) {
        return new byte[]{OpCode.PAD.getCode(), inputReg, Length, destReg};
    }

    public static byte[] prgGenerate(byte seedReg, byte lengthReg,  byte destReg) {
        return new byte[]{OpCode.PRG_GENERATE.getCode(), seedReg, lengthReg, destReg};
    }

    public static byte[] xor(byte inputA, byte inputB, byte destReg) {
        return new byte[]{OpCode.XOR.getCode(), inputA, inputB, destReg};
    }

    public static byte[] decrypt(byte keyReg, byte inputReg, byte destReg) {
        return new byte[]{OpCode.DECRYPT.getCode(), keyReg, inputReg, destReg};
    }

    public static byte[] encrypt(byte keyReg, byte inputReg, byte destReg) {
        return new byte[]{OpCode.ENCRYPT.getCode(), keyReg, inputReg, destReg};
    }

    public static byte[] forward(byte idReg) {
        return new byte[]{OpCode.FORWARD.getCode(), idReg};
    }


    public static byte[] concate(byte reg1, byte reg2, byte destReg) {
        return new byte[] {OpCode.CONCATE.getCode() ,reg1, reg2, destReg };
    }

    public static byte[] concateWithByteValue(byte reg1, byte value, byte destReg) {
        return new byte[] {OpCode.CONCATE_WITH_BYTE_VALUE.getCode() ,reg1, value, destReg };
    }

    public static byte[] forLoop(byte times, byte instrCount) {
        return new byte[]{OpCode.FOR.getCode(), times, instrCount};
    }

    public static byte[] mixNone() {
        return new byte[]{OpCode.MIX_NONE.getCode()};
    }

    public static byte[] mixTimed(byte delay) {
        return new byte[]{OpCode.MIX_TIMED.getCode(), delay};
    }

    public static byte[] mixThreshold(byte bufferSize) {
        return new byte[]{OpCode.MIX_THRESHOLD.getCode(), bufferSize};
    }

    public static byte[] mixPool(byte poolSize, byte outflowRate) {
        return new byte[]{OpCode.MIX_POOL.getCode(), poolSize, outflowRate};
    }

    public static byte[] mixPoisson(byte meanDelay) {
        return new byte[]{OpCode.MIX_POISSON.getCode(), meanDelay};
    }

    public static byte[] load(byte[] value, byte register) throws IOException {
        int length = value.length;
        if(length <= 0xFF) {
            return load1(value, register);
        } else if(length <= 0xFFFF) {
            return load2(value, register);
        } else if(length <= 0xFFFFFF) {
            return load3(value, register);
        } else {
            throw new IOException("Invalid length for load operation");
        }
    }

    public static byte[] load1(byte[] value, byte register) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(OpCode.LOAD1.getCode());
        out.write(value.length);
        out.write(value);
        out.write(register);
        return out.toByteArray();
    }

    public static byte[] load2(byte[] value, byte register) throws IOException {
        int length = value.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(OpCode.LOAD2.getCode());
        out.write((length >> 8) & 0xFF);
        out.write(length & 0xFF);
        out.write(value);
        out.write(register);
        return out.toByteArray();
    }

    public static byte[] load3(byte[] value, byte register) throws IOException {
        int length = value.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(OpCode.LOAD3.getCode());
        out.write((length >> 16) & 0xFF);
        out.write((length >> 8) & 0xFF);
        out.write(length & 0xFF);
        out.write(value);
        out.write(register);
        return out.toByteArray();
    }

    public static byte[] addRight(byte Register, byte addition, byte dest) {
        return new byte[]{OpCode.ADD.getCode(), Register, addition, dest};
    }
}