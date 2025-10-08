package microBenchmarks;

import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.MixFormats.PolySphinx.PolySphinxUtil;
import MasterThesisFormat.MixFormats.PolySphinx.SubHeader;
import MasterThesisFormat.MixNode;
import MasterThesisFormat.Params;
import MasterThesisFormat.pki.PkiEntry;
import MasterThesisFormat.pki.PkiGenerator;
import MasterThesisFormat.routing.RandomRoutingStrategy;
import kotlin.Pair;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class PolySphinxPackageProcessingBenchmark {
    private static final int RUNS = 30;

    private Params params;
    private Client client;
    private PkiGenerator generator;
    private byte[] replicationNode;
    private PkiEntry replication;
    private PkiEntry relay;
    private PkiEntry exit;
    private PkiEntry receiver;
    private List<byte[][]> suffixPaths;
    private List<ECPoint[]> keySets;
    private TestMixNode replicationMix;
    private TestMixNode relayMix;
    private TestMixNode exitMix;
    private final SecureRandom random = new SecureRandom();

    @Before
    public void setUp() throws Exception {
        params = new Params();
        client = new Client(params, new RandomRoutingStrategy());
        generator = new PkiGenerator(params);

        replication = generator.generateKeyPair();
        relay = generator.generateKeyPair();
        exit = generator.generateKeyPair();
        receiver = generator.generateKeyPair();

        replicationNode = ClientUtil.encodeNode(10, 0);
        byte[] relayNode = ClientUtil.encodeNode(11, 0);
        byte[] exitNode = ClientUtil.encodeNode(12, 0);
        byte[] receiverId = ClientUtil.encodeNode(1001, 0);

        suffixPaths = new ArrayList<>();
        suffixPaths.add(new byte[][]{relayNode, exitNode, receiverId});

        keySets = new ArrayList<>();
        keySets.add(new ECPoint[]{relay.pub(), exit.pub(), receiver.pub()});

        replicationMix = new TestMixNode("http://replication", replication.priv(), params);
        relayMix = new TestMixNode("http://relay", relay.priv(), params);
        exitMix = new TestMixNode("http://exit", exit.priv(), params);
    }

    @Test
    public void benchmarkPolySphinxProcessing() throws Exception {
        BenchmarkStats[] processingStats = {new BenchmarkStats(), new BenchmarkStats(), new BenchmarkStats()};

        for (int run = 0; run < RUNS; run++) {
            byte[] message = new byte[32 + random.nextInt(32)];
            random.nextBytes(message);
            byte[] seed = new byte[16];
            random.nextBytes(seed);

            Pair<InstructionPacket, List<SubHeader>> pair = PolySphinxUtil.createPolySphinxPacketForTests(
                    params, replicationNode, replication.pub(), suffixPaths, message, seed, keySets);
            InstructionPacket packet = pair.component1();
            byte[] raw = client.packInstructionPacket(packet);

            long replicationStart = System.nanoTime();
            List<InstructionPacket> replicationOutputs = replicationMix.process(raw);
            processingStats[0].record(System.nanoTime() - replicationStart);

            byte[] relayRaw = client.packInstructionPacket(replicationOutputs.get(0));

            long relayStart = System.nanoTime();
            List<InstructionPacket> relayOutputs = relayMix.process(relayRaw);
            processingStats[1].record(System.nanoTime() - relayStart);

            byte[] exitRaw = client.packInstructionPacket(relayOutputs.get(0));

            long exitStart = System.nanoTime();
            exitMix.process(exitRaw);
            processingStats[2].record(System.nanoTime() - exitStart);
        }

        for (int hop = 0; hop < 3; hop++) {
            System.out.printf("PolySphinx stage %d processing avg ns: %d (min=%d, max=%d)%n",
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