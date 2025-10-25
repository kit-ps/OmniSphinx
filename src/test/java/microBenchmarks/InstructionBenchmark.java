package microBenchmarks;

import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import MasterThesisFormat.VM.VM;
import MasterThesisFormat.VM.VMContext;
import MasterThesisFormat.VM.VMException;
import MasterThesisFormat.instruction.Instruction;
import MasterThesisFormat.instruction.InstructionRegister;
import MasterThesisFormat.instruction.OpCode;
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
    private static final int RUNS = 50;
    private static final byte REG_SOURCE = (byte) 0x20;
    private static final byte REG_DEST = (byte) 0x21;
    private static final byte REG_KEY = (byte) 0x22;
    private static final byte REG_A = (byte) 0x23;
    private static final byte REG_B = (byte) 0x24;
    private static final byte REG_C = (byte) 0x25;

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
        scenarios.put(OpCode.STORE_BYTES1.name(), this::storeBytesScenario);
        scenarios.put(OpCode.STORE_BYTES2.name(), this::storeBytesScenario);
        scenarios.put(OpCode.STORE_BYTES3.name(), this::storeBytesScenario);
        scenarios.put(OpCode.STORE_BYTES4.name(), this::storeBytesScenario);
        scenarios.put(OpCode.COMPUTE_SHARED_SECRET.name(), this::computeSharedSecretScenario);
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
        scenarios.put(OpCode.FIND_NEXT.name(), this::findNextScenario);
        scenarios.put(OpCode.FORWARD.name(), this::forwardScenario);
        scenarios.put(OpCode.MIX_NONE.name(), this::mixNoneScenario);
        scenarios.put(OpCode.MIX_TIMED.name(), this::mixTimedScenario);
        scenarios.put(OpCode.MIX_THRESHOLD.name(), this::mixThresholdScenario);
        scenarios.put(OpCode.MIX_POOL.name(), this::mixPoolScenario);
        scenarios.put(OpCode.MIX_POISSON.name(), this::mixPoissonScenario);
        scenarios.put(OpCode.LOAD1.name(), this::loadScenario);
        scenarios.put(OpCode.FOR.name(), this::forScenario);

        Map<String, BenchmarkStats> results = new LinkedHashMap<>();
        for (Map.Entry<String, InstructionScenario> entry : scenarios.entrySet()) {
            BenchmarkStats stats = runScenario(entry.getValue());
            results.put(entry.getKey(), stats);
            if (stats.getCount() > 0) {
                System.out.printf("%s avg ns: %d (min=%d, max=%d, errors=%d)%n",
                        entry.getKey(), stats.getAverage(), stats.getMin(), stats.getMax(), stats.getErrors());
            } else {
                System.out.printf("%s had only errors (%d). Last error: %s%n",
                        entry.getKey(), stats.getErrors(),
                        stats.getLastException() != null ? stats.getLastException().getMessage() : "none");
            }
        }

        assertFalse(results.isEmpty());
    }

    private BenchmarkStats runScenario(InstructionScenario scenario) throws Exception {
        BenchmarkStats stats = new BenchmarkStats();
        for (int i = 0; i < RUNS; i++) {
            Map<Byte, byte[]> registers = createBaseRegisters();
            byte[] instructions = scenario.createInstructions(registers);
            registers.put(InstructionRegister.INSTRUCTIONS.getCode(), instructions);
            VM vm = new VM(nodeSecret, params);
            try {
                long start = System.nanoTime();
                vm.interpret(new VMContext(registers));
                long duration = System.nanoTime() - start;
                stats.record(duration);
            } catch (VMException e) {
                stats.recordError(e);
            }
        }
        return stats;
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

    private byte[] storeBytesScenario(Map<Byte, byte[]> registers) {
        byte[] source = randomBytes(32 + random.nextInt(32));
        registers.put(REG_SOURCE, source);
        byte length = (byte) Math.min(16, source.length);
        if (length == 0) {
            length = 1;
        }
        return Instruction.storeBytes(REG_SOURCE, length, REG_DEST);
    }

    private byte[] computeSharedSecretScenario(Map<Byte, byte[]> registers) {
        BigInteger otherPriv = params.generatePrivateKey();
        ECPoint pub = params.derivePublicKey(otherPriv);
        registers.put(REG_SOURCE, SerializationUtils.encodeECPoint(pub));
        return Instruction.computeSharedSecret(REG_SOURCE, REG_DEST);
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

    private byte[] findNextScenario(Map<Byte, byte[]> registers) {
        int routingLen = 4 + random.nextInt(4);
        byte[] routing = randomBytes(routingLen);
        byte[] remainder = randomBytes(6);
        byte[] source = new byte[1 + routing.length + remainder.length];
        source[0] = (byte) routing.length;
        System.arraycopy(routing, 0, source, 1, routing.length);
        System.arraycopy(remainder, 0, source, 1 + routing.length, remainder.length);
        registers.put(REG_A, source);
        return new byte[]{OpCode.FIND_NEXT.getCode(), REG_A, REG_DEST};
    }

    private byte[] forwardScenario(Map<Byte, byte[]> registers) throws Exception {
        registers.put(REG_A, ClientUtil.encodeNode(500 + random.nextInt(500), 1));
        return Instruction.forward(REG_A);
    }

    private byte[] mixNoneScenario(Map<Byte, byte[]> registers) {
        return Instruction.mixNone();
    }

    private byte[] mixTimedScenario(Map<Byte, byte[]> registers) {
        byte delay = (byte) random.nextInt(2);
        return Instruction.mixTimed(delay);
    }

    private byte[] mixThresholdScenario(Map<Byte, byte[]> registers) {
        return Instruction.mixThreshold((byte) 2);
    }

    private byte[] mixPoolScenario(Map<Byte, byte[]> registers) {
        return Instruction.mixPool((byte) 2, (byte) 1);
    }

    private byte[] mixPoissonScenario(Map<Byte, byte[]> registers) {
        byte mean = (byte) random.nextInt(2);
        return Instruction.mixPoisson(mean);
    }

    private byte[] loadScenario(Map<Byte, byte[]> registers) throws IOException {
        byte[] value = randomBytes(12);
        return Instruction.load(value, REG_DEST);
    }

    private byte[] forScenario(Map<Byte, byte[]> registers) {
        byte times = (byte) (1 + random.nextInt(4));
        byte[] loopInstruction = Instruction.mixNone();
        return SerializationUtils.concatenate(Instruction.forLoop(times, (byte) 1), loopInstruction);
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