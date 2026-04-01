package microBenchmarks;

import OmniSphinx.Client;
import OmniSphinx.ClientUtil;
import OmniSphinx.InstructionPacket.InstructionPacket;
import OmniSphinx.InstructionPacket.InstructionPacketAndNextHop;
import OmniSphinx.MixFormats.MultiSphinx.MultiSphinxUtil;
import OmniSphinx.MixNode;
import OmniSphinx.Params;
import OmniSphinx.pki.PkiEntry;
import OmniSphinx.pki.PkiGenerator;
import OmniSphinx.routing.RandomRoutingStrategy;
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
    private static final int WARMUP_RUNS = 300;
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
            Map<String, BenchmarkStats> stageStats = new LinkedHashMap<>();

            for (int warmup = 0; warmup < WARMUP_RUNS; warmup++) {
                runPath(context, p, stageStats, false);
            }

            for (int run = 0; run < RUNS; run++) {
                runPath(context, p, stageStats, true);
            }

            assertHasDataForStage("Replication", p, stageStats);
            assertHasDataForStage("Relay", p, stageStats);
            reportStageBenchmarks(p, stageStats);
        }
    }

    private void runPath(MultiSphinxContext context, int p, Map<String, BenchmarkStats> statsByStage, boolean recordStats) throws Exception {
        int prefixHopCount = context.prefixHopCount;
        int suffixHopCount = context.suffixHopCount;
        byte[][] messages = new byte[p][];
        for (int i = 0; i < p; i++) {
            byte[] message = new byte[24];
            random.nextBytes(message);
            messages[i] = message;
        }

        InstructionPacket packet = MultiSphinxUtil.createMultiSphinxPacket(
                params, context.prefixNodeIds, context.prefixNodeKeys, context.suffixPaths, context.suffixKeys, messages, context.destinations);
        byte[] raw = client.packInstructionPacket(packet);

        List<InstructionPacketAndNextHop> replicationOutputs = null;
        for (int hop = 0; hop < prefixHopCount; hop++) {
            TestMixNode node = context.prefixMixNodes[hop];
            long start = System.nanoTime();
            replicationOutputs = node.processForTest(raw);
            double durationMicros = (System.nanoTime() - start) / 1_000.0;
            if (recordStats && hop == prefixHopCount - 1) {
                statsByStage.computeIfAbsent(labelForStageName("Replication", p), k -> new BenchmarkStats())
                        .record(durationMicros);
            }

            if (hop < prefixHopCount - 1) {
                raw = client.packInstructionPacket(replicationOutputs.get(0).getPacket());
            }
        }

        if (replicationOutputs == null) {
            return;
        }

        Deque<QueueEntry> queue = new ArrayDeque<>();
        for (InstructionPacketAndNextHop out : replicationOutputs) {
            queue.add(new QueueEntry(out.getPacket(), out.getNextHop(), prefixHopCount));
        }

        while (!queue.isEmpty()) {
            QueueEntry entry = queue.removeFirst();
            if (entry.stage >= prefixHopCount + suffixHopCount) {
                continue;
            }
            String hopKey = Base64.getEncoder().encodeToString(entry.nextHop);
            TestMixNode target = context.suffixMixNodes.get(hopKey);
            if (target == null) {
                continue;
            }
            List<InstructionPacketAndNextHop> outputs;
            byte[] rawpacket = client.packInstructionPacket(entry.packet);
            long start = System.nanoTime();
            outputs = target.processForTest(rawpacket);
            double durationMicros = (System.nanoTime() - start) / 1_000.0;

            if (recordStats && entry.stage == prefixHopCount) {
                statsByStage.computeIfAbsent(labelForStageName("Relay", p), k -> new BenchmarkStats())
                        .record(durationMicros);
            }
            int nextStage = entry.stage + 1;
            if (nextStage < prefixHopCount + suffixHopCount) {
                for (InstructionPacketAndNextHop output : outputs) {
                    queue.add(new QueueEntry(output.getPacket(), output.getNextHop(), nextStage));
                }
            }
        }
    }

    private void reportStageBenchmarks(int p, Map<String, BenchmarkStats> stats) throws Exception {
        reportSingleStage("Replication", p, stats);
        reportSingleStage("Relay", p, stats);
    }

    private void reportSingleStage(String stage, int p, Map<String, BenchmarkStats> stats) throws Exception {
        String label = labelForStageName(stage, p);
        BenchmarkStats stageStats = stats.get(label);
        if (stageStats == null) {
            System.out.printf("No stats recorded for %s%n", label);
            return;
        }

        Map<String, BenchmarkStats> stageMap = Map.of(label, stageStats);
        String title = "MultiSphinx " + stage + " p=" + p;
        BenchmarkReporter.printStats(title, stageMap);
        BenchmarkReporter.plotViolin(title, stageMap, "multisphinx-" + stage.toLowerCase() + "-p" + p + ".pdf");
        BenchmarkReporter.exportCsv(stageMap, String.format("multisphinx-%s-p%d.csv", stage.toLowerCase(), p));
    }

    private void assertHasDataForStage(String stage, int replicationCount, Map<String, BenchmarkStats> stats) {
        String label = labelForStageName(stage, replicationCount);
        BenchmarkStats stageStats = stats.get(label);
        assertTrue("No stats recorded for " + label, stageStats != null && stageStats.getCount() > 0);
    }

    private record QueueEntry(InstructionPacket packet, byte[] nextHop, int stage) {
    }

    private MultiSphinxContext prepareContext(int subPacketCount) throws Exception {
        int prefixHopCount = 1; // Replication -> Relay path starts with a single replication hop
        int suffixHopCount = 1; // ...and ends with a single relay hop

        byte[][] prefixNodeIds = new byte[prefixHopCount][];
        ECPoint[] prefixNodeKeys = new ECPoint[prefixHopCount];
        TestMixNode[] prefixMixNodes = new TestMixNode[prefixHopCount];
        for (int i = 0; i < prefixHopCount; i++) {
            PkiEntry entry = generator.generateKeyPair();
            prefixNodeIds[i] = Arrays.copyOf(ClientUtil.encodeNode(10 + i, 0), params.keyLength());
            prefixNodeKeys[i] = entry.pub();
            prefixMixNodes[i] = new TestMixNode("http://prefix-" + i, entry.priv(), params);
        }

        List<byte[][]> suffixPaths = new ArrayList<>();
        List<ECPoint[]> suffixKeys = new ArrayList<>();
        Map<String, TestMixNode> suffixMixNodes = new HashMap<>();
        byte[][] destinations = new byte[subPacketCount][];

        for (int packet = 0; packet < subPacketCount; packet++) {
            byte[][] path = new byte[suffixHopCount][];
            ECPoint[] keys = new ECPoint[suffixHopCount];
            for (int hop = 0; hop < suffixHopCount; hop++) {
                PkiEntry hopEntry = generator.generateKeyPair();
                path[hop] = Arrays.copyOf(ClientUtil.encodeNode(100 + (packet * 10) + hop, 0), params.keyLength());
                keys[hop] = hopEntry.pub();
                suffixMixNodes.put(Base64.getEncoder().encodeToString(path[hop]),
                        new TestMixNode("http://suffix-" + packet + "-" + hop, hopEntry.priv(), params));
            }
            suffixPaths.add(path);
            suffixKeys.add(keys);

            PkiEntry receiver = generator.generateKeyPair();
            destinations[packet] = Arrays.copyOf(ClientUtil.encodeNode(2000 + packet, 0), params.keyLength());
        }

        return new MultiSphinxContext(prefixHopCount, suffixHopCount, prefixNodeIds, prefixNodeKeys, prefixMixNodes, suffixPaths, suffixKeys, suffixMixNodes, destinations);
    }
    private record MultiSphinxContext(int prefixHopCount, int suffixHopCount, byte[][] prefixNodeIds, ECPoint[] prefixNodeKeys, TestMixNode[] prefixMixNodes, List<byte[][]> suffixPaths, List<ECPoint[]> suffixKeys, Map<String, TestMixNode> suffixMixNodes, byte[][] destinations) { }
    private String labelForStageName(String stage, int replicationCount) {
        return stage + " p=" + replicationCount;
    }
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
