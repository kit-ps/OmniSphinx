package microBenchmarks;

import OmniSphinx.ClientUtil;
import OmniSphinx.Params;
import OmniSphinx.SerializationUtils;
import OmniSphinx.VM.VM;
import OmniSphinx.VM.VMContext;
import OmniSphinx.instruction.Instruction;
import OmniSphinx.instruction.InstructionRegister;
import OmniSphinx.instruction.OpCode;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.assertFalse;

public class InstructionBenchmark {
    private static final int RUNS = 10000;
    private static final int WARMUP_RUNS = 200;
    private static final byte REG_SOURCE = (byte) 0x20;
    private static final byte REG_DEST = (byte) 0x21;
    private static final byte REG_KEY = (byte) 0x22;
    private static final byte REG_A = (byte) 0x23;
    private static final byte REG_B = (byte) 0x24;
    private static final byte REG_C = (byte) 0x25;
    private static final byte REG_LENGTH = (byte) 0x26;

    private final SecureRandom random = new SecureRandom();
    private Params params;
    private BigInteger nodeSecret;

    @Before
    public void setUp() {
        params = new Params();
        nodeSecret = params.generatePrivateKey();
    }

    @Test
    public void benchmarkInstructions() throws Exception {
        Map<String, InstructionScenario> scenarios = new LinkedHashMap<>();
        scenarios.put(OpCode.STOP.name(), this::stopScenario);
        scenarios.put(OpCode.STORE_BYTES1.name(), registers -> storeBytesScenario(registers, 1));
        scenarios.put(OpCode.STORE_BYTES2.name(), registers -> storeBytesScenario(registers, 2));
        scenarios.put(OpCode.STORE_BYTES3.name(), registers -> storeBytesScenario(registers, 3));
        scenarios.put(OpCode.STORE_BYTES4.name(), registers -> storeBytesScenario(registers, 4));
        scenarios.put(OpCode.STORE_MULTIPLE_BYTES.name(), this::storeMultipleScenario);
        scenarios.put(OpCode.HASH.name(), this::hashScenario);
        scenarios.put(OpCode.MAC.name(), this::macScenario);
        scenarios.put(OpCode.VERIFY.name(), this::verifyScenario);
        scenarios.put(OpCode.EXPONENT.name(), this::exponentScenario);
        scenarios.put(OpCode.PAD.name(), this::padScenario);
        scenarios.put(OpCode.PRG_GENERATE.name(), this::prgScenario);
        scenarios.put(OpCode.XOR.name(), this::xorScenario);
        scenarios.put(OpCode.DECRYPT.name(), this::decryptScenario);
        scenarios.put(OpCode.ENCRYPT.name(), this::encryptScenario);
        scenarios.put(OpCode.CONCATE.name(), this::concateScenario);
        scenarios.put(OpCode.CONCATE_WITH_BYTE_VALUE.name(), this::concateWithByteValueScenario);
        scenarios.put(OpCode.COPY.name(), this::copyScenario);
        scenarios.put(OpCode.ADD.name(), this::addScenario);
        scenarios.put(OpCode.FORWARD.name(), this::forwardScenario);

        scenarios.put(OpCode.LOAD1.name(), registers -> loadScenario(registers, 1));
        scenarios.put(OpCode.LOAD2.name(), registers -> loadScenario(registers, 2));
        scenarios.put(OpCode.LOAD3.name(), registers -> loadScenario(registers, 3));
        scenarios.put(OpCode.LOAD_MULTIPLE_BYTES.name(), this::loadMultipleScenario);
        scenarios.put(OpCode.FOR.name(), this::forScenario);

        Map<String, BenchmarkStats> results = new LinkedHashMap<>();
        for (Map.Entry<String, InstructionScenario> entry : scenarios.entrySet()) {
            BenchmarkStats stats = runScenario(entry.getValue());
            results.put(entry.getKey(), stats);
        }

        BenchmarkReporter.printStats("Instruction VM", results);
        assertFalse(results.isEmpty());
        assertFalse(results.values().stream().anyMatch(s -> s.getCount() == 0 && s.getErrors() == 0));
    }

    private BenchmarkStats runScenario(InstructionScenario scenario) throws Exception {
        BenchmarkStats stats = new BenchmarkStats();
        for (int warmup = 0; warmup < WARMUP_RUNS; warmup++) {
            try {
                executeScenario(scenario);
            } catch (Exception ignored) {
                // Warmup errors should not affect measurements.
            }
        }
        for (int i = 0; i < RUNS; i++) {
            try {
                double durationMicros = executeScenario(scenario);
                stats.record(durationMicros);
            } catch (Exception e) {
                stats.recordError(e);
            }
        }
        return stats;
    }

    private double executeScenario(InstructionScenario scenario) throws Exception {
        Map<Byte, byte[]> registers = createBaseRegisters();
        byte[] instructions = scenario.createInstructions(registers);
        registers.put(InstructionRegister.INSTRUCTIONS.getCode(), instructions);
        VM vm = new VM(nodeSecret, params);
        long start = System.nanoTime();
        vm.interpret(new VMContext(registers));
        long duration = System.nanoTime() - start;
        return duration / 1_000.0;
    }

    private Map<Byte, byte[]> createBaseRegisters() throws Exception {
        Map<Byte, byte[]> registers = new HashMap<>();
        BigInteger tmpSecret = params.generatePrivateKey();
        ECPoint point = params.derivePublicKey(tmpSecret);
        registers.put(InstructionRegister.NEXT_ALPHA.getCode(), SerializationUtils.encodeECPoint(point));
        registers.put(InstructionRegister.MAC.getCode(), randomBytes(params.keyLength()));
        registers.put(InstructionRegister.PAYLOAD.getCode(), randomBytes(32));
        registers.put(InstructionRegister.NEXT_HOP.getCode(), ClientUtil.encodeNode(random.nextInt(1000), 0));
        return registers;
    }

    private byte[] stopScenario(Map<Byte, byte[]> registers) {
        return Instruction.stop();
    }

    private byte[] storeBytesScenario(Map<Byte, byte[]> registers, int lengthBytes) throws IOException {
        int maxLength = switch (lengthBytes) {
            case 1 -> 64;
            case 2 -> 512;
            case 3 -> 1024;
            default -> 2048;
        };
        int length = 1 + random.nextInt(maxLength);
        byte[] source = randomBytes(length + random.nextInt(128));
        registers.put(REG_SOURCE, source);
        return buildStoreInstruction(lengthBytes, length);
    }

    private byte[] hashScenario(Map<Byte, byte[]> registers) {
        registers.put(REG_SOURCE, randomBytes(64));
        return Instruction.hash(REG_SOURCE, REG_DEST);
    }

    private byte[] macScenario(Map<Byte, byte[]> registers) {
        registers.put(REG_KEY, randomBytes(params.keyLength()));
        registers.put(REG_SOURCE, randomBytes(64));
        return Instruction.mac(REG_KEY, REG_SOURCE, REG_DEST);
    }

    private byte[] verifyScenario(Map<Byte, byte[]> registers) {
        byte[] value = randomBytes(32);
        registers.put(REG_A, value);
        registers.put(REG_B, value.clone());
        return Instruction.verify(REG_A, REG_B);
    }

    private byte[] exponentScenario(Map<Byte, byte[]> registers) {
        BigInteger priv = params.generatePrivateKey();
        ECPoint base = params.derivePublicKey(priv);
        registers.put(REG_A, SerializationUtils.encodeECPoint(base));
        BigInteger exponent = params.generatePrivateKey();
        registers.put(REG_B, exponent.toByteArray());
        return Instruction.exponent(REG_A, REG_B, REG_DEST, (byte) (params.keyLength() * 2));
    }

    private byte[] padScenario(Map<Byte, byte[]> registers) {
        registers.put(REG_SOURCE, randomBytes(8 + random.nextInt(8)));
        byte[] dest = randomBytes(16 + random.nextInt(16));
        registers.put(REG_DEST, dest);
        int maxLen = dest.length;
        byte length = (byte) (1 + random.nextInt(Math.max(1, maxLen)));
        return Instruction.pad(REG_SOURCE, length, REG_DEST);
    }

    private byte[] prgScenario(Map<Byte, byte[]> registers) {
        registers.put(REG_KEY, randomBytes(params.keyLength()));
        int maxLen = params.keyLength();
        int length = 1 + random.nextInt(Math.max(1, maxLen));
        registers.put(REG_A, toLengthBytes(length));
        return Instruction.prgGenerate(REG_KEY, REG_A, REG_DEST);
    }

    private byte[] toLengthBytes(int length) {
        if (length <= 0xFF) {
            return new byte[]{(byte) length};
        }
        return new byte[]{(byte) (length >> 8), (byte) length};
    }

    private byte[] xorScenario(Map<Byte, byte[]> registers) {
        byte[] data = randomBytes(32);
        registers.put(REG_A, data);
        registers.put(REG_B, data.clone());
        return Instruction.xor(REG_A, REG_B, REG_DEST);
    }

    private byte[] decryptScenario(Map<Byte, byte[]> registers) {
        byte[] key = randomBytes(params.keyLength());
        registers.put(REG_KEY, key);
        registers.put(REG_SOURCE, randomBytes(32));
        return Instruction.decrypt(REG_KEY, REG_SOURCE, REG_DEST);
    }

    private byte[] encryptScenario(Map<Byte, byte[]> registers) {
        byte[] key = randomBytes(params.keyLength());
        registers.put(REG_KEY, key);
        registers.put(REG_SOURCE, randomBytes(32));
        return Instruction.encrypt(REG_KEY, REG_SOURCE, REG_DEST);
    }

    private byte[] concateScenario(Map<Byte, byte[]> registers) {
        registers.put(REG_A, randomBytes(12));
        registers.put(REG_B, randomBytes(10));
        return Instruction.concate(REG_A, REG_B, REG_DEST);
    }


    private byte[] forwardScenario(Map<Byte, byte[]> registers) throws Exception {
        registers.put(REG_A, ClientUtil.encodeNode(500 + random.nextInt(500), 1));
        return Instruction.forward(REG_A);
    }

    private byte[] copyScenario(Map<Byte, byte[]> registers) {
        registers.put(REG_SOURCE, randomBytes(24));
        return Instruction.copy(REG_SOURCE, REG_DEST);
    }

    private byte[] addScenario(Map<Byte, byte[]> registers) {
        registers.put(REG_A, randomBytes(8));
        registers.put(REG_B, new byte[]{(byte) random.nextInt(4)});
        return Instruction.addRight(REG_A, REG_B, REG_DEST);
    }

    private byte[] concateWithByteValueScenario(Map<Byte, byte[]> registers) {
        registers.put(REG_A, randomBytes(6));
        byte value = (byte) random.nextInt(255);
        return Instruction.concateWithByteValue(REG_A, value, REG_DEST);
    }

    private byte[] storeMultipleScenario(Map<Byte, byte[]> registers) {
        int length = 1 + random.nextInt(32);
        registers.put(REG_SOURCE, randomBytes(length + random.nextInt(32)));
        registers.put(REG_LENGTH, toLengthBytes(length));
        return Instruction.storeMultipleBytes(REG_SOURCE, REG_LENGTH, REG_DEST);
    }

    private byte[] loadScenario(Map<Byte, byte[]> registers, int lengthBytes) throws IOException {
        int length = switch (lengthBytes) {
            case 1 -> 1 + random.nextInt(64);
            case 2 -> 256 + random.nextInt(256);
            case 3 -> 512 + random.nextInt(512);
            default -> 16;
        };
        byte[] value = randomBytes(length);
        return switch (lengthBytes) {
            case 1 -> Instruction.load1(value, REG_DEST);
            case 2 -> Instruction.load2(value, REG_DEST);
            case 3 -> Instruction.load3(value, REG_DEST);
            default -> Instruction.load(value, REG_DEST);
        };
    }

    private byte[] loadMultipleScenario(Map<Byte, byte[]> registers) {
        registers.put(REG_SOURCE, randomBytes(16));
        registers.put(REG_LENGTH, toLengthBytes(4));
        return new byte[]{OpCode.LOAD_MULTIPLE_BYTES.getCode(), REG_SOURCE, REG_LENGTH, REG_DEST};
    }

    private byte[] forScenario(Map<Byte, byte[]> registers) {
        byte times = (byte) (1 + random.nextInt(4));
        byte[] loopInstruction = Instruction.mixNone();
        return SerializationUtils.concatenate(Instruction.forLoop(times, (byte) 1), loopInstruction);
    }

    private byte[] buildStoreInstruction(int lengthBytes, int length) throws IOException {
        return switch (lengthBytes) {
            case 1 -> Instruction.storeBytes(REG_SOURCE, length, REG_DEST);
            case 2 -> new byte[]{OpCode.STORE_BYTES2.getCode(), REG_SOURCE, (byte) ((length >> 8) & 0xFF), (byte) (length & 0xFF), REG_DEST};
            case 3 -> new byte[]{OpCode.STORE_BYTES3.getCode(), REG_SOURCE,
                    (byte) ((length >> 16) & 0xFF),
                    (byte) ((length >> 8) & 0xFF),
                    (byte) (length & 0xFF),
                    REG_DEST};
            default -> new byte[]{OpCode.STORE_BYTES4.getCode(), REG_SOURCE,
                    (byte) ((length >> 24) & 0xFF),
                    (byte) ((length >> 16) & 0xFF),
                    (byte) ((length >> 8) & 0xFF),
                    (byte) (length & 0xFF),
                    REG_DEST};
        };
    }

    private byte[] randomBytes(int length) {
        byte[] data = new byte[length];
        random.nextBytes(data);
        return data;
    }

    @FunctionalInterface
    private interface InstructionScenario {
        byte[] createInstructions(Map<Byte, byte[]> registers) throws Exception;
    }
}