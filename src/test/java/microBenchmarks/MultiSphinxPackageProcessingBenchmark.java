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
    private static final int RUNS = 1000;
    private static final int PREFIX_HOPS = 2;
    private static final int SUFFIX_HOPS = 2;
    private static final int[] P_VALUES = {3, 5, 10};

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
    public void benchmarkMultiSphinxProcessing() throws Exception {
        for (int p : P_VALUES) {
            MultiSphinxContext context = prepareContext(p);
            Map<String, BenchmarkStats> stats = new LinkedHashMap<>();

            for (int run = 0; run < RUNS; run++) {
                byte[][] messages = new byte[p][];
                for (int i = 0; i < p; i++) {
                    byte[] message = new byte[32 + random.nextInt(32)];
                    random.nextBytes(message);
                    messages[i] = message;
                }

                InstructionPacket packet = MultiSphinxUtil.createMultiSphinxPacket(
                        params, context.prefixNodeIds, context.prefixNodeKeys, context.suffixPaths, context.suffixKeys, messages, context.destinations);
                byte[] raw = client.packInstructionPacket(packet);

                List<InstructionPacketAndNextHop> replicationOutputs = null;
                for (int hop = 0; hop < PREFIX_HOPS; hop++) {
                    long start = System.nanoTime();
                    replicationOutputs = context.prefixMixNodes[hop].processForTest(raw);
                    double durationMicros = (System.nanoTime() - start) / 1_000.0;
                    stats.computeIfAbsent(labelForStage(hop, p), k -> new BenchmarkStats())
                            .record(durationMicros);

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
                    TestMixNode target = context.suffixMixNodes.get(hopKey);
                    if (target == null) {
                        continue;
                    }

                    long start = System.nanoTime();
                    List<InstructionPacketAndNextHop> outputs = target.processForTest(client.packInstructionPacket(entry.packet));
                    double durationMicros = (System.nanoTime() - start) / 1_000.0;

                    stats.computeIfAbsent(labelForStage(entry.stage, p), k -> new BenchmarkStats())
                            .record(durationMicros);

                    for (InstructionPacketAndNextHop output : outputs) {
                        queue.add(new QueueEntry(output.getPacket(), output.getNextHop(), entry.stage + 1));
                    }
                }
            }

            BenchmarkReporter.printStats("MultiSphinx p=" + p, stats);
            BenchmarkReporter.plotViolin("MultiSphinx p=" + p, stats, "multisphinx-p" + p + ".pdf");
            assertTrue(stats.values().stream().anyMatch(s -> s.getCount() > 0));
        }
    }

    private record QueueEntry(InstructionPacket packet, byte[] nextHop, int stage) { }

    private MultiSphinxContext prepareContext(int subPacketCount) throws Exception {
        byte[][] prefixNodeIds = new byte[PREFIX_HOPS][];
        ECPoint[] prefixNodeKeys = new ECPoint[PREFIX_HOPS];
        TestMixNode[] prefixMixNodes = new TestMixNode[PREFIX_HOPS];
        for (int i = 0; i < PREFIX_HOPS; i++) {
            PkiEntry entry = generator.generateKeyPair();
            prefixNodeIds[i] = ClientUtil.encodeNode(10 + i, 0);
            prefixNodeKeys[i] = entry.pub();
            prefixMixNodes[i] = new TestMixNode("http://prefix-" + i, entry.priv(), params);
        }

        List<byte[][]> suffixPaths = new ArrayList<>();
        List<ECPoint[]> suffixKeys = new ArrayList<>();
        Map<String, TestMixNode> suffixMixNodes = new HashMap<>();
        byte[][] destinations = new byte[subPacketCount][];

        for (int packet = 0; packet < subPacketCount; packet++) {
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

        return new MultiSphinxContext(prefixNodeIds, prefixNodeKeys, prefixMixNodes, suffixPaths, suffixKeys, suffixMixNodes, destinations);
    }

    private String labelForStage(int stage, int subPacketCount) {
        if (stage == PREFIX_HOPS - 1) {
            return "Replication p=" + subPacketCount;
        }

        if (stage == PREFIX_HOPS + SUFFIX_HOPS - 1) {
            return "Exit p=" + subPacketCount;
        }

        return "Relay p=" + subPacketCount;
    }

    private record MultiSphinxContext(byte[][] prefixNodeIds, ECPoint[] prefixNodeKeys, TestMixNode[] prefixMixNodes, List<byte[][]> suffixPaths, List<ECPoint[]> suffixKeys, Map<String, TestMixNode> suffixMixNodes, byte[][] destinations) { }


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
