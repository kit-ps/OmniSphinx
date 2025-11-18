package microBenchmarks;

import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.InstructionPacket.InstructionPacketAndNextHop;
import MasterThesisFormat.MixFormats.MultiSphinx.MultiSphinxUtil;
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
import java.util.*;

import static org.junit.Assert.assertTrue;

public class MultiSphinxPackageProcessingBenchmark {
    private static final int RUNS = 30;
    private static final int PREFIX_HOPS = 2;
    private static final int SUFFIX_HOPS = 2;
    private static final int SUB_PACKET_COUNT = 2;

    private Params params;
    private Client client;
    private PkiGenerator generator;

    private byte[][] prefixNodeIds;
    private ECPoint[] prefixNodeKeys;
    private TestMixNode[] prefixMixNodes;

    private List<byte[][]> suffixPaths;
    private List<ECPoint[]> suffixKeys;
    private Map<String, TestMixNode> suffixMixNodes;
    private byte[][] destinations;
    private final SecureRandom random = new SecureRandom();

    @Before
    public void setUp() throws Exception {
        params = new Params();
        client = new Client(params, new RandomRoutingStrategy());
        generator = new PkiGenerator(params);

        prefixNodeIds = new byte[PREFIX_HOPS][];
        prefixNodeKeys = new ECPoint[PREFIX_HOPS];
        prefixMixNodes = new TestMixNode[PREFIX_HOPS];

        for (int i = 0; i < PREFIX_HOPS; i++) {
            PkiEntry entry = generator.generateKeyPair();
            prefixNodeIds[i] = ClientUtil.encodeNode(10 + i, 0);
            prefixNodeKeys[i] = entry.pub();
            prefixMixNodes[i] = new TestMixNode("http://prefix-" + i, entry.priv(), params);
        }

        suffixPaths = new ArrayList<>();
        suffixKeys = new ArrayList<>();
        suffixMixNodes = new HashMap<>();
        destinations = new byte[SUB_PACKET_COUNT][];

        for (int packet = 0; packet < SUB_PACKET_COUNT; packet++) {
            byte[][] path = new byte[SUFFIX_HOPS][];
            ECPoint[] keys = new ECPoint[SUFFIX_HOPS];
            for (int hop = 0; hop < SUFFIX_HOPS; hop++) {
                PkiEntry hopEntry = generator.generateKeyPair();
                path[hop] = ClientUtil.encodeNode(100 + (packet * 10) + hop, 0);
                keys[hop] = hopEntry.pub();
                suffixMixNodes.put(Base64.getEncoder().encodeToString(path[hop]),
                        new TestMixNode("http://suffix-" + packet + "-" + hop, hopEntry.priv(), params));
            }
            suffixPaths.add(path);
            suffixKeys.add(keys);

            PkiEntry receiver = generator.generateKeyPair();
            destinations[packet] = Arrays.copyOf(ClientUtil.encodeNode(2000 + packet, 0), params.keyLength());
        }
    }

    @Test
    public void benchmarkMultiSphinxProcessing() throws Exception {
        BenchmarkStats[] processingStats = new BenchmarkStats[PREFIX_HOPS + SUFFIX_HOPS];
        for (int i = 0; i < processingStats.length; i++) {
            processingStats[i] = new BenchmarkStats();
        }

        for (int run = 0; run < RUNS; run++) {
            byte[][] messages = new byte[SUB_PACKET_COUNT][];
            for (int i = 0; i < SUB_PACKET_COUNT; i++) {
                byte[] message = new byte[32 + random.nextInt(32)];
                random.nextBytes(message);
                messages[i] = message;
            }

            InstructionPacket packet = MultiSphinxUtil.createMultiSphinxPacket(
                    params, prefixNodeIds, prefixNodeKeys, suffixPaths, suffixKeys, messages, destinations);
            byte[] raw = client.packInstructionPacket(packet);

            List<InstructionPacketAndNextHop> replicationOutputs = null;
            for (int hop = 0; hop < PREFIX_HOPS; hop++) {
                long start = System.nanoTime();
                replicationOutputs = prefixMixNodes[hop].processForTest(raw);
                processingStats[hop].record(System.nanoTime() - start);

                if (hop < PREFIX_HOPS - 1) {
                    raw = client.packInstructionPacket(replicationOutputs.get(0).getPacket());
                }
            }

            Deque<QueueEntry> queue = new ArrayDeque<>();
            for (InstructionPacketAndNextHop out : replicationOutputs) {
                queue.add(new QueueEntry(out.getPacket(), out.getNextHop(), PREFIX_HOPS));
            }

            while (!queue.isEmpty()) {
                QueueEntry entry = queue.removeFirst();
                if (entry.stage >= PREFIX_HOPS + SUFFIX_HOPS) {
                    continue;
                }
                String hopKey = Base64.getEncoder().encodeToString(entry.nextHop);
                TestMixNode target = suffixMixNodes.get(hopKey);
                if (target == null) {
                    continue;
                }

                long start = System.nanoTime();
                List<InstructionPacketAndNextHop> outputs = target.processForTest(client.packInstructionPacket(entry.packet));
                processingStats[entry.stage].record(System.nanoTime() - start);

                for (InstructionPacketAndNextHop output : outputs) {
                    queue.add(new QueueEntry(output.getPacket(), output.getNextHop(), entry.stage + 1));
                }
            }
        }

        for (int hop = 0; hop < processingStats.length; hop++) {
            System.out.printf("MultiSphinx stage %d processing avg ns: %d (min=%d, max=%d)%n",
                    hop + 1,
                    (long) processingStats[hop].getAverage(),
                    (long) processingStats[hop].getMin(),
                    (long) processingStats[hop].getMax());
        }

        assertTrue(processingStats[0].getCount() > 0);
    }

    private record QueueEntry(InstructionPacket packet, byte[] nextHop, int stage) { }

    private static class TestMixNode extends MixNode {
        private final List<InstructionPacketAndNextHop> forwarded = new ArrayList<>();

        TestMixNode(String url, BigInteger secret, Params params) throws Exception {
            super(url.getBytes(StandardCharsets.UTF_8), secret, params);
        }

        @Override
        public void startListener(int port) {
            // Disable HTTP listener for benchmark tests.
        }

        @Override
        protected void sendToNextNode(byte[] nextHop, InstructionPacket packet) {
            forwarded.add(new InstructionPacketAndNextHop(nextHop, packet));
        }

        public List<InstructionPacketAndNextHop> processForTest(byte[] rawPacket) throws Exception {
            forwarded.clear();
            super.process(rawPacket);
            return new ArrayList<>(forwarded);
        }
    }
}
