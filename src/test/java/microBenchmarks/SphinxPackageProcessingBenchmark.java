package microBenchmarks;

import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.MixNode;
import MasterThesisFormat.Params;
import MasterThesisFormat.pki.PkiEntry;
import MasterThesisFormat.pki.PkiGenerator;
import MasterThesisFormat.routing.RandomRoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

import static org.junit.Assert.assertTrue;

public class SphinxPackageProcessingBenchmark {
    private static final int RUNS = 1000;
    private static final int pathLength = 6;

    private Params params;
    private Client client;
    private PkiGenerator generator;
    private final SecureRandom random = new SecureRandom();

    @Before
    public void setUp() throws Exception {
        params = new Params();
        client = new Client(params, new RandomRoutingStrategy());
        generator = new PkiGenerator(params);
    }

    @Test
    public void benchmarkSphinxProcessing() throws Exception {
        SphinxContext context = prepareContext(pathLength);
        Map<String, BenchmarkStats> stats = new LinkedHashMap<>();

        for (int run = 0; run < RUNS; run++) {
            byte[] message = new byte[32 + random.nextInt(32)];
            random.nextBytes(message);
            InstructionPacket packet = client.createSphinxInstructionPacket(context.nodeList, context.keys, context.destination, message);
            byte[] raw = client.packInstructionPacket(packet);

            byte[] current = raw;
            for (int hop = 0; hop < context.privs.length; hop++) {
                TestMixNode mixNode = context.mixNodes[hop];
                long start = System.nanoTime();
                List<InstructionPacket> outputs = mixNode.process(current);
                long duration = System.nanoTime() - start;
                String label = hop == context.privs.length - 1 ? "Exit" : "Relay ";
                stats.computeIfAbsent(label, l -> new BenchmarkStats()).record(duration);

                if (hop < context.privs.length - 1 && !outputs.isEmpty()) {
                    current = client.packInstructionPacket(outputs.get(0));
                }
            }
        }
        BenchmarkReporter.printStats("Sphinx " , stats);
        BenchmarkReporter.plotViolin("Sphinx " , stats, "sphinx-p" + ".png");
        assertTrue(stats.values().stream().anyMatch(s -> s.getCount() > 0));
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
}