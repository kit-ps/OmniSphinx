package OmniSphinx.benchmarks;

import OmniSphinx.ClientUtil;
import OmniSphinx.Params;
import OmniSphinx.SerializationUtils;
import OmniSphinx.VM.VM;
import OmniSphinx.VM.VMContext;
import OmniSphinx.VM.VMOutput;
import OmniSphinx.instruction.Instruction;
import OmniSphinx.instruction.InstructionRegister;
import OmniSphinx.instruction.OpCode;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.nio.file.Path;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;
import java.util.HashMap;
import java.util.List;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@BenchmarkMode(Mode.SampleTime)
@State(Scope.Benchmark)
public class InstructionBenchmark {
    private static final byte REG_SOURCE = (byte) 0x20;
    private static final byte REG_DEST = (byte) 0x21;
    private static final byte REG_KEY = (byte) 0x22;
    private static final byte REG_A = (byte) 0x23;
    private static final byte REG_B = (byte) 0x24;
    private static final byte REG_C = (byte) 0x25;
    private static final byte REG_LENGTH = (byte) 0x26;

    public static class InstructionState {
        SecureRandom random;
        Params params;
        BigInteger nodeSecret;
        Map<Byte, byte[]> registers;
        byte[] scenario;
        VM vm;

        InstructionState() {
            random = new SecureRandom();
            params = new Params();
            nodeSecret = params.generatePrivateKey();
            try {
                registers = createBaseRegisters();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            vm = new VM(nodeSecret, params);
        }

        void setInstructionRegister() {
            registers.put(InstructionRegister.INSTRUCTIONS.getCode(), scenario);
        }

        Map<Byte, byte[]> createBaseRegisters() throws Exception {
            Map<Byte, byte[]> registers = new HashMap<>();
            BigInteger tmpSecret = params.generatePrivateKey();
            ECPoint point = params.derivePublicKey(tmpSecret);
            registers.put(InstructionRegister.NEXT_ALPHA.getCode(), SerializationUtils.encodeECPoint(point));
            registers.put(InstructionRegister.MAC.getCode(), randomBytes(params.keyLength()));
            registers.put(InstructionRegister.PAYLOAD.getCode(), randomBytes(32));
            registers.put(InstructionRegister.NEXT_HOP.getCode(), ClientUtil.encodeNode(random.nextInt(1000), 0));
            return registers;
        }

        byte[] storeBytesScenario(Map<Byte, byte[]> registers, int lengthBytes) throws IOException {
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

        byte[] toLengthBytes(int length) {
            if (length <= 0xFF) {
                return new byte[]{(byte) length};
            }
            return new byte[]{(byte) (length >> 8), (byte) length};
        }

        byte[] loadScenario(Map<Byte, byte[]> registers, int lengthBytes) throws IOException {
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

        byte[] randomBytes(int length) {
            byte[] data = new byte[length];
            random.nextBytes(data);
            return data;
        }
    }

    @State(Scope.Benchmark)
    public static class OpStop extends InstructionState {
        @Setup
        public void setup() {
            scenario = stopScenario(registers);
            setInstructionRegister();
        }

        private byte[] stopScenario(Map<Byte, byte[]> registers) {
            return Instruction.stop();
        }
    }

    @Benchmark
    public List<VMOutput> opStop(OpStop state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpStoreBytes1 extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = storeBytesScenario(registers, 1);
            setInstructionRegister();
        }
    }

    @Benchmark
    public List<VMOutput> opStoreBytes1(OpStoreBytes1 state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpStoreBytes2 extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = storeBytesScenario(registers, 2);
            setInstructionRegister();
        }
    }

    @Benchmark
    public List<VMOutput> opStoreBytes2(OpStoreBytes2 state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpStoreBytes3 extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = storeBytesScenario(registers, 3);
            setInstructionRegister();
        }
    }

    @Benchmark
    public List<VMOutput> opStoreBytes3(OpStoreBytes3 state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpStoreBytes4 extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = storeBytesScenario(registers, 4);
            setInstructionRegister();
        }
    }

    @Benchmark
    public List<VMOutput> opStoreBytes4(OpStoreBytes4 state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpStoreMultipleBytes extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = storeMultipleScenario(registers);
            setInstructionRegister();
        }

        private byte[] storeMultipleScenario(Map<Byte, byte[]> registers) {
            int length = 1 + random.nextInt(32);
            registers.put(REG_SOURCE, randomBytes(length + random.nextInt(32)));
            registers.put(REG_LENGTH, toLengthBytes(length));
            return Instruction.storeMultipleBytes(REG_SOURCE, REG_LENGTH, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opStoreMultipleBytes(OpStoreMultipleBytes state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpHash extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = hashScenario(registers);
            setInstructionRegister();
        }

        private byte[] hashScenario(Map<Byte, byte[]> registers) {
            registers.put(REG_SOURCE, randomBytes(64));
            return Instruction.hash(REG_SOURCE, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opHash(OpHash state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpMac extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = macScenario(registers);
            setInstructionRegister();
        }

        private byte[] macScenario(Map<Byte, byte[]> registers) {
            registers.put(REG_KEY, randomBytes(params.keyLength()));
            registers.put(REG_SOURCE, randomBytes(64));
            return Instruction.mac(REG_KEY, REG_SOURCE, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opMac(OpMac state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpVerify extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = verifyScenario(registers);
            setInstructionRegister();
        }

        private byte[] verifyScenario(Map<Byte, byte[]> registers) {
            byte[] value = randomBytes(32);
            registers.put(REG_A, value);
            registers.put(REG_B, value.clone());
            return Instruction.verify(REG_A, REG_B);
        }
    }

    @Benchmark
    public List<VMOutput> opVerify(OpVerify state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpExponent extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = exponentScenario(registers);
            setInstructionRegister();
        }

        private byte[] exponentScenario(Map<Byte, byte[]> registers) {
            BigInteger priv = params.generatePrivateKey();
            ECPoint base = params.derivePublicKey(priv);
            registers.put(REG_A, SerializationUtils.encodeECPoint(base));
            BigInteger exponent = params.generatePrivateKey();
            registers.put(REG_B, exponent.toByteArray());
            return Instruction.exponent(REG_A, REG_B, REG_DEST, (byte) (params.keyLength() * 2));
        }
    }

    @Benchmark
    public List<VMOutput> opExponent(OpExponent state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpPad extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = padScenario(registers);
            setInstructionRegister();
        }

        private byte[] padScenario(Map<Byte, byte[]> registers) {
            registers.put(REG_SOURCE, randomBytes(8 + random.nextInt(8)));
            byte[] dest = randomBytes(16 + random.nextInt(16));
            registers.put(REG_DEST, dest);
            int maxLen = dest.length;
            byte length = (byte) (1 + random.nextInt(Math.max(1, maxLen)));
            return Instruction.pad(REG_SOURCE, length, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opPad(OpPad state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpPrgGenerate extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = prgScenario(registers);
            setInstructionRegister();
        }

        private byte[] prgScenario(Map<Byte, byte[]> registers) {
            registers.put(REG_KEY, randomBytes(params.keyLength()));
            int maxLen = params.keyLength();
            int length = 1 + random.nextInt(Math.max(1, maxLen));
            registers.put(REG_A, toLengthBytes(length));
            return Instruction.prgGenerate(REG_KEY, REG_A, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opPrgGenerate(OpPrgGenerate state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpXor extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = xorScenario(registers);
            setInstructionRegister();
        }

        private byte[] xorScenario(Map<Byte, byte[]> registers) {
            byte[] data = randomBytes(32);
            registers.put(REG_A, data);
            registers.put(REG_B, data.clone());
            return Instruction.xor(REG_A, REG_B, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opXor(OpXor state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpDecrypt extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = decryptScenario(registers);
            setInstructionRegister();
        }

        private byte[] decryptScenario(Map<Byte, byte[]> registers) {
            byte[] key = randomBytes(params.keyLength());
            registers.put(REG_KEY, key);
            registers.put(REG_SOURCE, randomBytes(32));
            return Instruction.decrypt(REG_KEY, REG_SOURCE, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opDecrypt(OpDecrypt state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpEncrypt extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = encryptScenario(registers);
            setInstructionRegister();
        }

        private byte[] encryptScenario(Map<Byte, byte[]> registers) {
            byte[] key = randomBytes(params.keyLength());
            registers.put(REG_KEY, key);
            registers.put(REG_SOURCE, randomBytes(32));
            return Instruction.encrypt(REG_KEY, REG_SOURCE, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opEncrypt(OpEncrypt state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpConcat extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = concatScenario(registers);
            setInstructionRegister();
        }

        private byte[] concatScenario(Map<Byte, byte[]> registers) {
            registers.put(REG_A, randomBytes(12));
            registers.put(REG_B, randomBytes(10));
            return Instruction.concate(REG_A, REG_B, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opConcat(OpConcat state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpConcatWithByte extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = concatWithByteScenario(registers);
            setInstructionRegister();
        }

        private byte[] concatWithByteScenario(Map<Byte, byte[]> registers) {
            registers.put(REG_A, randomBytes(6));
            byte value = (byte) random.nextInt(255);
            return Instruction.concateWithByteValue(REG_A, value, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opConcatWithByte(OpConcatWithByte state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpCopy extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = copyScenario(registers);
            setInstructionRegister();
        }

        private byte[] copyScenario(Map<Byte, byte[]> registers) {
            registers.put(REG_SOURCE, randomBytes(24));
            return Instruction.copy(REG_SOURCE, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opCopy(OpCopy state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpAdd extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = addScenario(registers);
            setInstructionRegister();
        }

        private byte[] addScenario(Map<Byte, byte[]> registers) {
            registers.put(REG_A, randomBytes(8));
            registers.put(REG_B, new byte[]{(byte) random.nextInt(4)});
            return Instruction.addRight(REG_A, REG_B, REG_DEST);
        }
    }

    @Benchmark
    public List<VMOutput> opAdd(OpAdd state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpForward extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws Exception {
            scenario = forwardScenario(registers);
            setInstructionRegister();
            registers.put(InstructionRegister.NEXT_INSTRUCTIONS.getCode(), Instruction.stop());
        }

        private byte[] forwardScenario(Map<Byte, byte[]> registers) throws Exception {
            registers.put(REG_A, ClientUtil.encodeNode(500 + random.nextInt(500), 1));
            return Instruction.forward(REG_A);
        }
    }

    @Benchmark
    public List<VMOutput> opForward(OpForward state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpLoadBytes1 extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = loadScenario(registers, 1);
            setInstructionRegister();
        }
    }

    @Benchmark
    public List<VMOutput> opLoadBytes1(OpLoadBytes1 state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpLoadBytes2 extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = loadScenario(registers, 2);
            setInstructionRegister();
        }
    }

    @Benchmark
    public List<VMOutput> opLoadBytes2(OpLoadBytes2 state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpLoadBytes3 extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = loadScenario(registers, 3);
            setInstructionRegister();
        }
    }

    @Benchmark
    public List<VMOutput> opLoadBytes3(OpLoadBytes3 state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpLoadMultipleBytes extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = loadMultipleScenario(registers);
            setInstructionRegister();
        }

        private byte[] loadMultipleScenario(Map<Byte, byte[]> registers) {
            registers.put(REG_SOURCE, randomBytes(16));
            registers.put(REG_LENGTH, toLengthBytes(4));
            return new byte[]{OpCode.LOAD_MULTIPLE_BYTES.getCode(), REG_SOURCE, REG_LENGTH, REG_DEST};
        }
    }

    @Benchmark
    public List<VMOutput> opLoadMultipleBytes(OpLoadMultipleBytes state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    @State(Scope.Benchmark)
    public static class OpFor extends InstructionState {
        @Setup(Level.Invocation)
        public void setup() throws IOException {
            scenario = forScenario(registers);
            setInstructionRegister();
        }

        private byte[] forScenario(Map<Byte, byte[]> registers) {
            byte times = (byte) (1 + random.nextInt(4));
            byte[] loopInstruction = Instruction.mixNone();
            return SerializationUtils.concatenate(Instruction.forLoop(times, (byte) 1), loopInstruction);
        }
    }

    @Benchmark
    public List<VMOutput> opFor(OpFor state) throws Exception {
        return state.vm.interpret(new VMContext(state.registers));
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(InstructionBenchmark.class.getSimpleName())
            .forks(1)
            .resultFormat(ResultFormatType.JSON)
            .result(Path.of("target", "benchmarks", "instructions.json").toString())
            .build();

        new Runner(opt).run();
    }
}
