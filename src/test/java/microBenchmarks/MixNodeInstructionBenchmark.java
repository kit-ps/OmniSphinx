package microBenchmarks;

import OmniSphinx.ClientUtil;
import OmniSphinx.Params;
import OmniSphinx.SerializationUtils;
import OmniSphinx.VM.VM;
import OmniSphinx.VM.VMContext;
import OmniSphinx.VM.VMException;
import OmniSphinx.instruction.Instruction;
import OmniSphinx.instruction.InstructionRegister;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertFalse;

public class MixNodeInstructionBenchmark {
    private static final int RUNS = 10;
    private static final byte REG_BASE = (byte) 0x30;
    private static final byte REG_EXP = (byte) 0x31;
    private static final byte REG_DEST = (byte) 0x32;

    private final SecureRandom random = new SecureRandom();
    private Params params;
    private BigInteger nodeSecret;

    @Before
    public void setUp() {
        params = new Params();
        nodeSecret = params.generatePrivateKey();
    }

    @Test
    public void benchmarkNestedForInstructionLengths() throws Exception {
        int[] instructionCounts = {8, 16, 32, 64, 96, 128, 160, 200};
        Map<Integer, BenchmarkStats> results = new HashMap<>();

        for (int count : instructionCounts) {
            BenchmarkStats stats = new BenchmarkStats();
            for (int run = 0; run < RUNS; run++) {
                Map<Byte, byte[]> registers = createBaseRegisters();
                registers.put(REG_BASE, createRandomPoint());
                registers.put(REG_EXP, params.generatePrivateKey().toByteArray());
                byte[] instructions = buildNestedForProgram(count);
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
            results.put(count, stats);
            if (stats.getCount() > 0) {
                System.out.printf("Nested FOR instruction count %d avg ns: %d (min=%d, max=%d)%n",
                        count, stats.getAverage(), stats.getMin(), stats.getMax());
            } else {
                System.out.printf("Nested FOR instruction count %d failed: %s%n",
                        count, stats.getLastException() != null ? stats.getLastException().getMessage() : "unknown error");
            }
        }

        assertFalse(results.isEmpty());
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

    private byte[] buildNestedForProgram(int instructionCount) throws Exception {
        int outer = Math.max(1, Math.min(255, (int) Math.round(Math.sqrt(instructionCount))));
        int inner = Math.max(1, Math.min(255, (int) Math.ceil((double) instructionCount / outer)));
        byte[] exponent = Instruction.exponent(REG_BASE, REG_EXP, REG_DEST, (byte) (params.keyLength() * 2));
        byte[] innerLoop = SerializationUtils.concatenate(Instruction.forLoop((byte) inner, (byte) 1), exponent);
        return SerializationUtils.concatenate(Instruction.forLoop((byte) outer, (byte) 1), innerLoop);
    }

    private byte[] createRandomPoint() {
        BigInteger priv = params.generatePrivateKey();
        ECPoint point = params.derivePublicKey(priv);
        return SerializationUtils.encodeECPoint(point);
    }

    private byte[] randomBytes(int length) {
        byte[] data = new byte[length];
        random.nextBytes(data);
        return data;
    }
}