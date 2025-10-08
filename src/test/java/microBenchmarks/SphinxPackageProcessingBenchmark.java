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

import static org.junit.Assert.assertTrue;

public class SphinxPackageProcessingBenchmark {
    private static final int RUNS = 30;

    private Params params;
    private Client client;
    private PkiGenerator generator;
    private byte[][] nodeList;
    private ECPoint[] keys;
    private BigInteger[] privs;
    private byte[] destination;
    private TestMixNode[] mixNodes;
    private final SecureRandom random = new SecureRandom();

    @Before
    public void setUp() throws Exception {
        params = new Params();
        client = new Client(params, new RandomRoutingStrategy());
        generator = new PkiGenerator(params);

        PkiEntry n1 = generator.generateKeyPair();
        PkiEntry n2 = generator.generateKeyPair();
        PkiEntry n3 = generator.generateKeyPair();
        nodeList = new byte[][]{
                ClientUtil.encodeNode(1, 0),
                ClientUtil.encodeNode(2, 0),
                ClientUtil.encodeNode(3, 0)
        };
        keys = new ECPoint[]{n1.pub(), n2.pub(), n3.pub()};
        privs = new BigInteger[]{n1.priv(), n2.priv(), n3.priv()};
        destination = ClientUtil.encodeNode(1000, 0);

        mixNodes = new TestMixNode[privs.length];
        for (int i = 0; i < privs.length; i++) {
            mixNodes[i] = new TestMixNode("http://node-" + i, privs[i], params);
        }
    }

    @Test
    public void benchmarkSphinxProcessing() throws Exception {
        BenchmarkStats[] processingStats = {new BenchmarkStats(), new BenchmarkStats(), new BenchmarkStats()};

        for (int run = 0; run < RUNS; run++) {
            byte[] message = new byte[32 + random.nextInt(32)];
            random.nextBytes(message);
            InstructionPacket packet = client.createSphinxInstructionPacket(nodeList, keys, destination, message);
            byte[] raw = client.packInstructionPacket(packet);

            byte[] current = raw;
            for (int hop = 0; hop < privs.length; hop++) {
                TestMixNode mixNode = mixNodes[hop];
                long start = System.nanoTime();
                List<InstructionPacket> outputs = mixNode.process(current);
                long duration = System.nanoTime() - start;
                processingStats[hop].record(duration);

                if (hop < privs.length - 1 && !outputs.isEmpty()) {
                    current = client.packInstructionPacket(outputs.get(0));
                }
            }
        }

        for (int hop = 0; hop < privs.length; hop++) {
            System.out.printf("Sphinx hop %d processing avg ns: %d (min=%d, max=%d)%n",
                    hop + 1, processingStats[hop].getAverage(), processingStats[hop].getMin(), processingStats[hop].getMax());
        }

        assertTrue(processingStats[0].getCount() > 0);
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