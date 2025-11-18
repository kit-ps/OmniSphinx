package MasterThesisFormat.VM;

import MasterThesisFormat.Params;
import MasterThesisFormat.instruction.InstructionRegister;
import MasterThesisFormat.instruction.OpCode;

import java.math.BigInteger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static MasterThesisFormat.VM.VMUtil.*;


public class VM {
    private final BigInteger nodeSecret;
    private Map<Byte, byte[]> registers;
    private Params params;
    private List<VMOutput> vmOutputs;
    private boolean stopRequested;

    public VM(BigInteger nodeSecret, Params params) {
        this.nodeSecret = nodeSecret;
        this.params = params;
    }

    public List<VMOutput> interpret(VMContext context) throws VMException {
        registers = context.registers;
        vmOutputs = new ArrayList<>();
        stopRequested = false;
        interpretInstructions(registers.get(InstructionRegister.INSTRUCTIONS.getCode()));
        return vmOutputs;
    }

    private void interpretInstructions(byte[] instructions) throws VMException {
        for (int pc = 0; pc < instructions.length && !stopRequested;) {
            OpCode opcode = OpCode.fromByte(instructions[pc++]);
            try {
                switch (opcode) {
                    case STOP -> stopRequested = true;
                    case FOR -> {
                        int times = Byte.toUnsignedInt(instructions[pc++]);
                        int instrCount = Byte.toUnsignedInt(instructions[pc++]);

                        int programCounter = pc;
                        pc = executeFor(instructions, times, instrCount, programCounter);
                    }
                    case STORE_BYTES1 -> pc = handleStore(instructions, pc, 1);
                    case STORE_BYTES2 -> pc = handleStore(instructions, pc, 2);
                    case STORE_BYTES3 -> pc = handleStore(instructions, pc, 3);
                    case STORE_BYTES4 -> pc = handleStore(instructions, pc, 4);
                    case STORE_MULTIPLE_BYTES -> {
                        byte source = instructions[pc++];
                        byte lengthReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        storeMultipleBytes(source, lengthReg, destReg);
                    }

                    case HASH -> {
                        byte inputReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        hash(inputReg, destReg);
                    }
                    case MAC -> {
                        byte keyReg = instructions[pc++];
                        byte dataReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        mac(keyReg, dataReg, destReg);
                    }
                    case VERIFY -> {
                        byte expectedReg = instructions[pc++];
                        byte computedReg = instructions[pc++];
                        verify(expectedReg, computedReg);
                    }
                    case EXPONENT -> {
                        byte reg1 = instructions[pc++];
                        byte reg2 = instructions[pc++];
                        byte destReg = instructions[pc++];
                        byte outputLen = instructions[pc++];
                        exponent(reg1, reg2, destReg, outputLen);
                    }
                    case PAD -> {
                        byte padReg = instructions[pc++];
                        byte length = instructions[pc++];
                        byte destReg = instructions[pc++];
                        pad(padReg, length, destReg);
                    }
                    case PRG_GENERATE -> {
                        byte seedReg = instructions[pc++];
                        byte lengthREG = instructions[pc++];
                        byte destReg = instructions[pc++];
                        prgGenerate(seedReg, lengthREG, destReg);
                    }
                    case XOR -> {
                        byte inputA = instructions[pc++];
                        byte inputB = instructions[pc++];
                        byte destReg = instructions[pc++];
                        xor(inputA, inputB, destReg);
                    }
                    case COPY -> {
                        byte sourceReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        copy(sourceReg, destReg);
                    }
                    case ADD -> {
                        byte augend = instructions[pc++];
                        byte addend = instructions[pc++];
                        byte destReg = instructions[pc++];
                        add(augend, addend, destReg);
                    }
                    case DECRYPT -> {
                        byte keyReg = instructions[pc++];
                        byte inputReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        decrypt(keyReg, inputReg, destReg);
                    }
                    case CONCATE -> {
                        byte reg1 = instructions[pc++];
                        byte reg2 = instructions[pc++];
                        byte destReg = instructions[pc++];
                        concate(reg1, reg2, destReg);
                    }
                    case CONCATE_WITH_BYTE_VALUE -> {
                        byte reg1 = instructions[pc++];
                        byte value = instructions[pc++];
                        byte destReg = instructions[pc++];
                        concateWithByteValue(reg1, value, destReg);
                    }

                    case FORWARD -> {
                        byte idReg = instructions[pc++];
                        forward(idReg);
                    }
                    case ENCRYPT -> {
                        byte keyReg = instructions[pc++];
                        byte inputReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        encrypt(keyReg, inputReg, destReg);
                    }
                    case MIX_NONE -> {
                        applyMixNone();
                    }

                    case MIX_TIMED -> {
                        byte delay = instructions[pc++];
                        applyTimedMix(delay);
                    }

                    case MIX_THRESHOLD -> {
                        byte bufferSize = instructions[pc++];
                        applyThresholdMix(bufferSize);
                    }

                    case MIX_POOL -> {
                        byte poolSize = instructions[pc++];
                        byte outflowRate = instructions[pc++];
                        applyPoolMix(poolSize, outflowRate);
                    }

                    case MIX_POISSON -> {
                        byte meanDelay = instructions[pc++];
                        applyPoissonMix(meanDelay);
                    }

                    case LOAD1 -> pc = handleLoad(instructions, pc, 1);
                    case LOAD2 -> pc = handleLoad(instructions, pc, 2);
                    case LOAD3 -> pc = handleLoad(instructions, pc, 3);
                    default -> throw new VMException("Unknown OpCode: " + opcode);
                }
                if (stopRequested) {
                    break;
                }
            } catch (VMException e) {
                throw new VMException("Error at instruction " + opcode + ": " + e.getMessage(), e);
            }
        }
    }

    private int executeFor(byte[] instructions, int times, int instrCount, int programCounter) throws VMException {
        int blockEnd = programCounter;

        for (int i = 0; i < times && !stopRequested; i++) {
            int innerPc = programCounter;

            for (int j = 0; j < instrCount && !stopRequested; j++) {
                OpCode innerOpcode = OpCode.fromByte(instructions[innerPc++]);

                switch (innerOpcode) {
                    case STOP -> stopRequested = true;
                    case STORE_BYTES1 -> innerPc = handleStore(instructions, innerPc, 1);
                    case STORE_BYTES2 -> innerPc = handleStore(instructions, innerPc, 2);
                    case STORE_BYTES3 -> innerPc = handleStore(instructions, innerPc, 3);
                    case STORE_BYTES4 -> innerPc = handleStore(instructions, innerPc, 4);
                    case STORE_MULTIPLE_BYTES -> {
                        byte source = instructions[innerPc++];
                        byte lengthReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        storeMultipleBytes(source, lengthReg, destReg);
                    }

                    case HASH -> {
                        byte inputReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        hash(inputReg, destReg);
                    }
                    case MAC -> {
                        byte keyReg = instructions[innerPc++];
                        byte dataReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        mac(keyReg, dataReg, destReg);
                    }
                    case VERIFY -> {
                        byte expectedReg = instructions[innerPc++];
                        byte computedReg = instructions[innerPc++];
                        verify(expectedReg, computedReg);
                    }
                    case EXPONENT -> {
                        byte reg1 = instructions[innerPc++];
                        byte reg2 = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        byte outputLen = instructions[innerPc++];
                        exponent(reg1, reg2, destReg, outputLen);
                    }
                    case PAD -> {
                        byte padReg = instructions[innerPc++];
                        byte length = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        pad(padReg, length, destReg);
                    }
                    case PRG_GENERATE -> {
                        byte seedReg = instructions[innerPc++];
                        byte lengthREG = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        prgGenerate(seedReg, lengthREG, destReg);
                    }
                    case XOR -> {
                        byte inputA = instructions[innerPc++];
                        byte inputB = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        xor(inputA, inputB, destReg);
                    }
                    case COPY -> {
                        byte sourceReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        copy(sourceReg, destReg);
                    }
                    case ADD -> {
                        byte augend = instructions[innerPc++];
                        byte addend = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        add(augend, addend, destReg);
                    }
                    case DECRYPT -> {
                        byte keyReg = instructions[innerPc++];
                        byte inputReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        decrypt(keyReg, inputReg, destReg);
                    }
                    case CONCATE -> {
                        byte reg1 = instructions[innerPc++];
                        byte reg2 = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        concate(reg1, reg2, destReg);
                    }
                    case CONCATE_WITH_BYTE_VALUE -> {
                        byte reg1 = instructions[innerPc++];
                        byte value = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        concateWithByteValue(reg1, value, destReg);
                    }
                    case FORWARD -> {
                        byte idReg = instructions[innerPc++];
                        forward(idReg);
                    }
                    case ENCRYPT -> {
                        byte keyReg = instructions[innerPc++];
                        byte inputReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        encrypt(keyReg, inputReg, destReg);
                    }
                    case MIX_NONE -> {
                        applyMixNone();
                    }

                    case MIX_TIMED -> {
                        byte delay = instructions[innerPc++];
                        applyTimedMix(delay);
                    }

                    case MIX_THRESHOLD -> {
                        byte bufferSize = instructions[innerPc++];
                        applyThresholdMix(bufferSize);
                    }

                    case MIX_POOL -> {
                        byte poolSize = instructions[innerPc++];
                        byte outflowRate = instructions[innerPc++];
                        applyPoolMix(poolSize, outflowRate);
                    }

                    case MIX_POISSON -> {
                        byte meanDelay = instructions[innerPc++];
                        applyPoissonMix(meanDelay);
                    }

                    case LOAD1 -> innerPc = handleLoad(instructions, innerPc, 1);
                    case LOAD2 -> innerPc = handleLoad(instructions, innerPc, 2);
                    case LOAD3 -> innerPc = handleLoad(instructions, innerPc, 3);
                    default -> throw new VMException("Unknown OpCode in FOR block: " + innerOpcode);
                }
                if (stopRequested) {
                    break;
                }
            }
            blockEnd = innerPc;
        }
        return blockEnd;
    }


    private int handleLoad(byte[] instructions, int pc, int lengthBytes) throws VMException {
        if (pc + lengthBytes > instructions.length) {
            throw new VMException("LOAD length prefix out of bounds");
        }

        int len = 0;
        for (int i = 0; i < lengthBytes; i++) {
            len = (len << 8) | Byte.toUnsignedInt(instructions[pc++]);
        }

        if (pc + len > instructions.length) {
            throw new VMException("LOAD length out of bounds");
        }

        int end = pc + len;
        if (end >= instructions.length) {
            throw new VMException("LOAD missing destination register");
        }

        byte[] value = Arrays.copyOfRange(instructions, pc, end);
        pc = end;
        byte destReg = instructions[pc++];
        load(value, destReg);
        return pc;
    }

    private int handleStore(byte[] instructions, int pc, int lengthBytes) throws VMException {
        if (pc >= instructions.length) {
            throw new VMException("STORE missing source register");
        }

        byte source = instructions[pc++];
        int length = readImmediateLength(instructions, pc, lengthBytes);
        pc += lengthBytes;

        if (pc >= instructions.length) {
            throw new VMException("STORE missing destination register");
        }

        byte destReg = instructions[pc++];
        storeBytes(source, length, destReg);
        return pc;
    }

    private int readImmediateLength(byte[] instructions, int pc, int lengthBytes) throws VMException {
        if (pc + lengthBytes > instructions.length) {
            throw new VMException("STORE length out of bounds");
        }

        int length = 0;
        for (int i = 0; i < lengthBytes; i++) {
            length = (length << 8) | Byte.toUnsignedInt(instructions[pc++]);
        }
        return length;
    }

    private void storeBytes(byte source, int length, byte destReg) throws VMException {
        if (length < 0) {
            throw new VMException("STORE length must be non-negative");
        }

        byte[] src = registers.get(source);
        if (src == null) {
            throw new VMException("STORE source register not initialized");
        }

        if (length > src.length) {
            throw new VMException("storeByte out of bounds");
        }

        byte[] extracted = Arrays.copyOfRange(src, 0, length);
        registers.put(destReg, extracted);

        byte[] newSrc = Arrays.copyOfRange(src, length, src.length);
        registers.put(source, newSrc);
    }

    private void storeMultipleBytes(byte source, byte lengthReg, byte destReg) throws VMException {
        byte[] lengthBytes = registers.get(lengthReg);
        if (lengthBytes == null || lengthBytes.length == 0) {
            throw new VMException("STORE_MULTIPLE length register not initialized");
        }

        int length = lengthBytes.length <= Integer.BYTES ? toUnsignedInt(lengthBytes) : lengthBytes.length;
        storeBytes(source, length, destReg);
    }


    private void hash(byte inputReg, byte destReg) throws VMException {
        byte[] input = registers.get(inputReg);
        byte[] result = params.hash(input);
        registers.put(destReg, result);
    }

    private void mac(byte keyReg, byte dataReg, byte destReg) throws VMException {
        byte[] key = registers.get(keyReg);
        byte[] data = registers.get(dataReg);

        if (key == null) {
            throw new VMException("MAC key register not initialized");
        }
        if (data == null) {
            throw new VMException("MAC data register not initialized");
        }

        byte[] mac = params.mac(key, data);
        registers.put(destReg, mac);
    }

    private void verify(byte expectedReg, byte computedReg) throws VMException {
        if (!Arrays.equals(registers.get(expectedReg), registers.get(computedReg))) {
            throw new VMException("MAC verification failed");
        }
    }

    private void exponent(byte baseReg, byte expReg, byte destReg, byte outputLength) throws VMException {
        try {
            byte[] result = params.exponent(registers.get(baseReg), registers.get(expReg));
            registers.put(destReg, result);
        } catch (Exception e) {
            throw new VMException("exponend failed: " + e.getMessage(), e);
        }
    }

    private void pad(byte inputReg, byte targetLength, byte destReg) throws VMException {
        int len = Byte.toUnsignedInt(targetLength);
        byte[] input = registers.get(inputReg);

        if (len > registers.get(destReg).length) {
            throw new VMException("Target length exceeds destination register size.");
        }

        byte[] output = new byte[registers.get(destReg).length + len];
        Arrays.fill(output, (byte) 0x00);

        System.arraycopy(input, 0, output, 0, input.length);

        registers.put(destReg, output);
    }


    private void prgGenerate(byte seedReg, byte lengthReg, byte destReg) throws VMException {
        byte[] seed = registers.get(seedReg);
        byte[] lengthBytes = registers.get(lengthReg);

        if (seed == null) {
            throw new VMException("PRG seed register not initialized");
        }
        if (lengthBytes == null || lengthBytes.length == 0) {
            throw new VMException("PRG length register not initialized");
        }

        int outputLength = lengthBytes.length <= Integer.BYTES ? toUnsignedInt(lengthBytes) : lengthBytes.length;
        if (outputLength < 0) {
            throw new VMException("Invalid PRG output length");
        }

        byte[] stream = params.prg(seed, outputLength);
        registers.put(destReg, stream);
    }

    private int toUnsignedInt(byte[] value) {
        int result = 0;
        for (byte b : value) {
            result = (result << 8) | Byte.toUnsignedInt(b);
        }
        return result;
    }

    private void copy(byte sourceReg, byte destReg) throws VMException {
        byte[] value = registers.get(sourceReg);
        if (value == null) {
            throw new VMException("COPY source register not initialized");
        }

        registers.put(destReg, Arrays.copyOf(value, value.length));
    }

    private void xor(byte inputA, byte inputB, byte destReg) throws VMException {
        byte[] a = registers.get(inputA);
        byte[] b = registers.get(inputB);

        byte[] result;
        if (a.length < b.length) {
            result = new byte[a.length];
        } else {
            result = new byte[b.length];
        }

        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        registers.put(destReg, result);
    }

    private void add(byte augendReg, byte addendReg, byte destReg) throws VMException {
        byte[] augend = registers.get(augendReg);
        byte[] addend = registers.get(addendReg);



        if (augend == null) {
            throw new VMException("ADD augend register not initialized");
        }
        if (addend == null) {
            throw new VMException("ADD addend register not initialized");
        }

        int value = 0;
        for(byte b: addend) {
            value = (value << 8) + (b & 0xFF);
        }

        for(int i = 0; i < value; i++) {
            augend = increment(augend);
        }

        registers.put(destReg, augend);
    }

    private byte[] increment(byte[] value) throws VMException {
        if (value == null) {
            throw new VMException("INCREMENT register not initialized");
        }

        for (int i = value.length - 1; i >= 0; i--) {
            value[i]++;
            if (value[i] != 0) break;
        }
        return value;
    }

    private void decrypt(byte keyReg, byte inputReg, byte destReg) throws VMException {
        byte[] result = params.decrypt(registers.get(keyReg), registers.get(inputReg));
        registers.put(destReg, result);
    }

    private void encrypt(byte keyReg, byte inputReg, byte destReg) throws VMException {
        byte[] result = params.encrypt(registers.get(keyReg), registers.get(inputReg));
        registers.put(destReg, result);
    }

    private void findNext(byte sourceReg, byte destReg) throws VMException {
        byte[] src = registers.get(sourceReg);

        if (src.length < 1) {
            throw new VMException("findNext: source too short");
        }

        int len = Byte.toUnsignedInt(src[0]); // erstes Byte gibt Länge an
        if (src.length < 1 + len) {
            throw new VMException("findNext: insufficient bytes for routing info");
        }

        // Extrahiere Routing-Info
        byte[] routing = Arrays.copyOfRange(src, 1, 1 + len);
        registers.put(destReg, routing);

        // Entferne die genutzten Bytes aus source
        byte[] remainder = Arrays.copyOfRange(src, 1 + len, src.length);
        registers.put(sourceReg, remainder);
    }

    private void concate(byte reg1, byte reg2, byte destReg) throws VMException {
        byte[] data1 = registers.get(reg1);
        byte[] data2 = registers.get(reg2);

        if(data1 == null) {
            data1 = new byte[0];
        }

        if(data2 == null) {
            data2 = new byte[0];
        }

        byte[] result = new byte[data1.length + data2.length];
        System.arraycopy(data1, 0, result, 0, data1.length);
        System.arraycopy(data2, 0, result, data1.length, data2.length);

        registers.put(destReg, result);
    }

    private void concateWithByteValue(byte reg1, byte value, byte destReg) throws VMException {
        byte[] data = registers.get(reg1);
        if (data == null) {
            throw new VMException("Source register for CONCATE_WITH_BYTE_VALUE not initialized");
        }

        byte[] result = Arrays.copyOf(data, data.length + 1);
        result[result.length - 1] = value;
        registers.put(destReg, result);
    }

    private void load(byte[] value, byte destReg) {
        registers.put(destReg, value);
    }


    private void forward(byte idReg) throws VMException {
        byte[] nextHop = registers.get(idReg);
        byte[] nextAlpha = registers.get(InstructionRegister.NEXT_ALPHA.getCode());
        byte[] instructions = registers.get(InstructionRegister.NEXT_INSTRUCTIONS.getCode());
        byte[] mac = registers.get(InstructionRegister.MAC.getCode());
        byte[] payload = registers.get(InstructionRegister.PAYLOAD.getCode());

        if (nextHop == null || nextAlpha == null || instructions == null || mac == null || payload == null) {
            throw new VMException("Missing register for forward operation");
        }

        VMOutput out = new VMOutput(nextHop, nextAlpha, instructions, mac, payload);
        vmOutputs.add(out);
    }

    private void applyMixNone() {
        // intentionally left blank
    }

    private void applyTimedMix(byte delay) throws VMException {
        try {
            Thread.sleep(Byte.toUnsignedInt(delay));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VMException("Timed mix interrupted");
        }
    }

    private void applyPoissonMix(byte meanDelay) throws VMException {
        double mean = Byte.toUnsignedInt(meanDelay);
        double sampled = -mean * Math.log(1.0 - Math.random());
        try {
            Thread.sleep((long) sampled);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VMException("Poisson mix interrupted");
        }
    }

    private void applyThresholdMix(byte bufferSize) throws VMException {
        throw new VMException("Threshold mix not implemented yet: Buffer size = " + bufferSize);
    }

    private void applyPoolMix(byte poolSize, byte outflowRate) throws VMException {
        throw new VMException("Pool mix not implemented yet: PoolSize = " + poolSize + ", Outflow = " + outflowRate);
    }
}

