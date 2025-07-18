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

    public VM(BigInteger nodeSecret, Params params) {
        this.nodeSecret = nodeSecret;
        this.params = params;
    }

    public List<VMOutput> interpret(VMContext context) throws VMException {
        registers = context.registers;
        vmOutputs = new ArrayList<>();
        interpretInstructions(registers.get(InstructionRegister.INSTRUCTIONS.getCode()));
        return vmOutputs;
    }

    private void interpretInstructions(byte[] instructions) throws VMException {
        for (int pc = 0; pc < instructions.length;) {
            OpCode opcode = OpCode.fromByte(instructions[pc++]);
            try {
                switch (opcode) {
                    case FOR -> {
                        int times = Byte.toUnsignedInt(instructions[pc++]);
                        int instrCount = Byte.toUnsignedInt(instructions[pc++]);

                        int programCounter = pc;
                        pc = executeFor(instructions, times, instrCount, programCounter);
                    }
                    case STORE_BYTES -> {
                        byte source = instructions[pc++];
                        byte length = instructions[pc++];
                        byte destReg = instructions[pc++];
                        storeBytes(source, length, destReg);
                    }
                    case COMPUTE_SHARED_SECRET -> {
                        byte pubKeyReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        computeSharedSecret(pubKeyReg, destReg);
                    }
                    case HASH -> {
                        byte inputReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        hash(inputReg, destReg);
                    }
                    case MAC -> {
                        byte keyReg = instructions[pc++];
                        byte dataReg = instructions[pc++];
                        byte length = instructions[pc++];
                        byte destReg = instructions[pc++];
                        mac(keyReg, dataReg, length, destReg);
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
                        byte destReg = instructions[pc++];
                        prgGenerate(seedReg, destReg);
                    }
                    case XOR -> {
                        byte inputA = instructions[pc++];
                        byte inputB = instructions[pc++];
                        byte destReg = instructions[pc++];
                        xor(inputA, inputB, destReg);
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
                    case FIND_NEXT -> {
                        byte sourceReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        findNext(sourceReg, destReg);
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

                    case LOAD -> {
                        int len = Byte.toUnsignedInt(instructions[pc++]);
                        if (pc + len > instructions.length) {
                            throw new VMException("LOAD length out of bounds");
                        }
                        byte[] value = Arrays.copyOfRange(instructions, pc, pc + len);
                        pc += len;
                        byte destReg = instructions[pc++];
                        load(value, destReg);
                    }
                    default -> throw new VMException("Unknown OpCode: " + opcode);
                }
            } catch (VMException e) {
                throw new VMException("Error at instruction " + opcode + ": " + e.getMessage(), e);
            }
        }
    }

    private int executeFor(byte[] instructions, int times, int instrCount, int programCounter) throws VMException {
        int blockEnd = programCounter;

        for (int i = 0; i < times; i++) {
            int innerPc = programCounter;

            for (int j = 0; j < instrCount; j++) {
                OpCode innerOpcode = OpCode.fromByte(instructions[innerPc++]);

                switch (innerOpcode) {
                    case STORE_BYTES -> {
                        byte source = instructions[innerPc++];
                        byte length = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        storeBytes(source, length, destReg);
                    }
                    case COMPUTE_SHARED_SECRET -> {
                        byte pubKeyReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        computeSharedSecret(pubKeyReg, destReg);
                    }
                    case HASH -> {
                        byte inputReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        hash(inputReg, destReg);
                    }
                    case MAC -> {
                        byte keyReg = instructions[innerPc++];
                        byte dataReg = instructions[innerPc++];
                        byte length = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        mac(keyReg, dataReg,length, destReg);
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
                        byte destReg = instructions[innerPc++];
                        prgGenerate(seedReg, destReg);
                    }
                    case XOR -> {
                        byte inputA = instructions[innerPc++];
                        byte inputB = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        xor(inputA, inputB, destReg);
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
                    case FIND_NEXT -> {
                        byte sourceReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        findNext(sourceReg, destReg);
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

                    case LOAD -> {
                        int len = Byte.toUnsignedInt(instructions[innerPc++]);
                        if (innerPc + len > instructions.length) {
                            throw new VMException("LOAD length out of bounds");
                        }
                        byte[] value = Arrays.copyOfRange(instructions, innerPc, innerPc + len);
                        innerPc += len;
                        byte destReg = instructions[innerPc++];
                        load(value, destReg);
                    }
                    default -> throw new VMException("Unknown OpCode in FOR block: " + innerOpcode);
                }
            }
            blockEnd = innerPc;
        }
        return blockEnd;
    }


    private void storeBytes(byte source, byte length, byte destReg) throws VMException {
        int startByte = 0;
        int lengthBytes = Byte.toUnsignedInt(length);

        byte[] src = registers.get(source);


        if (startByte + lengthBytes > src.length) {
            throw new VMException("storeByte out of bounds");
        }

        byte[] extracted = Arrays.copyOfRange(src, startByte, startByte + lengthBytes);
        registers.put(destReg, extracted);

        // Entferne aus source
        byte[] newSrc = new byte[src.length - lengthBytes];
        System.arraycopy(src, 0, newSrc, 0, startByte);
        System.arraycopy(src, startByte + lengthBytes, newSrc, startByte, src.length - (startByte + lengthBytes));
        registers.put(source, newSrc);
    }

    private void computeSharedSecret(byte pubKeyReg, byte destReg) throws VMException {
        try {
            byte[] pubKeyBytes = registers.get(pubKeyReg);
            byte[] result = params.computeSharedSecret(nodeSecret, pubKeyBytes);
            registers.put(destReg, result);
        } catch (Exception e) {
            throw new VMException("Shared secret computation failed: " + e.getMessage(), e);
        }
    }



    private void hash(byte inputReg, byte destReg) throws VMException {
        byte[] input = registers.get(inputReg);
        byte[] result = params.hash(input);
        registers.put(destReg, result);
    }

    private void mac(byte keyReg, byte dataReg, byte length, byte destReg) throws VMException {
        byte[] mac = params.mac(registers.get(keyReg), registers.get(dataReg));
        registers.put(destReg, slice(mac, Byte.toUnsignedInt(length)));
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


    private void prgGenerate(byte seedReg, byte destReg) throws VMException {
        byte[] stream = params.prg(registers.get(seedReg));
        registers.put(destReg, stream);
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

        byte[] result = new byte[data1.length + data2.length];
        System.arraycopy(data1, 0, result, 0, data1.length);
        System.arraycopy(data2, 0, result, data1.length, data2.length);

        registers.put(destReg, result);
    }

    private void load(byte[] value, byte destReg) {
        registers.put(destReg, value);
    }


    private void forward(byte idReg) throws VMException {
        byte[] nextHop = registers.get(idReg);
        byte[] nextAlpha = registers.get(InstructionRegister.NEXT_ALPHA.getCode());
        byte[] instructions = registers.get(InstructionRegister.INSTRUCTIONS.getCode());
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

