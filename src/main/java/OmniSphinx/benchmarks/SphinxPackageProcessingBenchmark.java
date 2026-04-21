package OmniSphinx.benchmarks;

import OmniSphinx.Client;
import OmniSphinx.ClientUtil;
import OmniSphinx.InstructionPacket.InstructionPacket;
import OmniSphinx.crypto.ECCGroup;
import OmniSphinx.MixNode;
import OmniSphinx.Params;
import OmniSphinx.pki.PkiEntry;
import OmniSphinx.pki.PkiGenerator;
import OmniSphinx.routing.RandomRoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@BenchmarkMode(Mode.SampleTime)
@State(Scope.Benchmark)
public class SphinxPackageProcessingBenchmark {
    private static final int RUNS = 3000;
    private static final int pathLength = 5;
    private static final int warmUp = 300;
    private Params params;
    private Client client;
    private PkiGenerator generator;
    private final SecureRandom random = new SecureRandom();

    byte[] packetRelay;
    byte[] packetExit;
    TestMixNode nodeRelay;
    TestMixNode nodeExit;

    @Setup
    public void setUp() throws Exception {
        params = new Params(16, 1045, 0, new ECCGroup(), 196);
        client = new Client(params, new RandomRoutingStrategy());
        generator = new PkiGenerator(params);
    }

    @Setup(Level.Invocation)
    public void setupInvocation() throws Exception {
        SphinxContext context = prepareContext(pathLength);

        byte[] message = new byte[1024];
        random.nextBytes(message);
        InstructionPacket packet = client.createSphinxInstructionPacket(context.nodeList, context.keys, context.destination, message);
        byte[] raw = client.packInstructionPacket(packet);

        nodeRelay = context.mixNodes[0];
        packetRelay = raw;

        byte[] current = raw;
        for (int hop = 0; hop < context.privs.length; hop++) {
            TestMixNode mixNode = context.mixNodes[hop];
            List<InstructionPacket> outputs = mixNode.process(current);
            if (hop < context.privs.length - 1 && !outputs.isEmpty()) {
                current = client.packInstructionPacket(outputs.get(0));
            }

            nodeExit = mixNode;
            packetExit = current;
        }
    }

    @Benchmark
    public List<InstructionPacket> relay() throws Exception {
        return nodeRelay.process(packetRelay);
    }

    @Benchmark
    public List<InstructionPacket> exit() throws Exception {
        return nodeExit.process(packetExit);
    }

    private SphinxContext prepareContext (int pathLength) throws Exception {
            byte[][] nodeList = new byte[pathLength][];
            ECPoint[] keys = new ECPoint[pathLength];
            BigInteger[] privs = new BigInteger[pathLength];
            TestMixNode[] mixNodes = new TestMixNode[pathLength];
            byte[] destination = ClientUtil.encodeNode(1000, 0);

            for (int i = 0; i < pathLength; i++) {
                PkiEntry entry = generator.generateKeyPair();
                nodeList[i] = ClientUtil.encodeNode(i + 1, 0);
                keys[i] = entry.pub();
                privs[i] = entry.priv();
                mixNodes[i] = new TestMixNode("http://node-" + i, privs[i], params);
            }

            return new SphinxContext(nodeList, keys, privs, destination, mixNodes);
        }


    private record SphinxContext(byte[][] nodeList, ECPoint[] keys, BigInteger[] privs, byte[] destination,
                                 TestMixNode[] mixNodes) {
    }

    private static class TestMixNode extends MixNode {
        TestMixNode(String url, BigInteger secret, Params params) throws Exception {
            super(url.getBytes(StandardCharsets.UTF_8), secret, params);
        }

        @Override
        public void startListener(int port) {
            // Disable HTTP listener for benchmark tests.
        }

        @Override
        protected void sendToNextNode(byte[] nextHop, InstructionPacket packet) {
            // Suppress network forwarding during benchmarks.
        }
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include("\\b" + SphinxPackageProcessingBenchmark.class.getSimpleName())
            .forks(1)
            .resultFormat(ResultFormatType.JSON)
            .result(Path.of("target", "benchmarks", "sphinx-processing.json").toString())
            .build();

        new Runner(opt).run();
    }
}
