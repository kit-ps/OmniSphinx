package microBenchmarks;

import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.InstructionPacket.InstructionPacketAndNextHop;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

import static org.junit.Assert.assertTrue;

public class PolySphinxPackageProcessingBenchmark {
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
    public void benchmarkPolySphinxProcessing() throws Exception {
        for (int p : P_VALUES) {
            if (p == 3) {
                params.setInstructionTotalSize(1400);
            }
            if (p == 5) {
                params.setInstructionTotalSize(2000);
            }
            if (p == 10) {
                params.setInstructionTotalSize(4000);
            }
            PolySphinxContext context = prepareContext(p);
            Map<String, BenchmarkStats> stats = new LinkedHashMap<>();

            for (int warmup = 0; warmup < WARMUP_RUNS; warmup++) {
                runIteration(context, p, stats, false);
            }
            for (int run = 0; run < RUNS; run++) {
                runIteration(context, p, stats, true);

            }

            BenchmarkReporter.printStats("PolySphinx p=" + p, stats);
            BenchmarkReporter.plotViolin("PolySphinx p=" + p, stats, "polysphinx-p" + p + ".pdf");
            assertTrue(stats.values().stream().anyMatch(s -> s.getCount() > 0));
        }
    }

    private PolySphinxContext prepareContext(int replicationCount) throws Exception {
        PkiEntry replication = generator.generateKeyPair();
        byte[] replicationNode = ClientUtil.encodeNode(10, 0);

        List<byte[][]> suffixPaths = new ArrayList<>();
        List<ECPoint[]> keySets = new ArrayList<>();
        List<byte[]> receivers = new ArrayList<>();
        Map<String, TestMixNode> mixNodes = new LinkedHashMap<>();
        List<String> exitNodeKeys = new ArrayList<>();


        for (int i = 0; i < replicationCount; i++) {
            List<byte[]> pathNodes = new ArrayList<>();
            List<ECPoint> keys = new ArrayList<>();

            for (int hop = 0; hop < 4; hop++) {
                PkiEntry relay = generator.generateKeyPair();
                byte[] relayNode = ClientUtil.encodeNode(20 + (i * 10) + hop, 0);
                pathNodes.add(relayNode);
                keys.add(relay.pub());
                mixNodes.put(Base64.getEncoder().encodeToString(relayNode), new TestMixNode("http://relay-" + i + "-" + hop, relay.priv(), params));
            }

            PkiEntry exit = generator.generateKeyPair();
            byte[] exitNode = ClientUtil.encodeNode(21 + (i * 10), 0);
            pathNodes.add(exitNode);
            keys.add(exit.pub());
            String exitKey = Base64.getEncoder().encodeToString(exitNode);
            exitNodeKeys.add(exitKey);
            mixNodes.put(exitKey, new TestMixNode("http://exit-" + i, exit.priv(), params));

            suffixPaths.add(pathNodes.toArray(new byte[0][]));
            keySets.add(keys.toArray(new ECPoint[0]));
            receivers.add(ClientUtil.encodeNode(1001 + i, 0));
        }


        TestMixNode replicationMix = new TestMixNode("http://replication", replication.priv(), params);

        return new PolySphinxContext(replication, replicationNode, suffixPaths, keySets, receivers, mixNodes, exitNodeKeys, replicationMix);
    }

    private void runIteration(PolySphinxContext context, int p, Map<String, BenchmarkStats> stats, boolean recordStats) throws Exception {
        byte[] message = new byte[32 + random.nextInt(32)];
        random.nextBytes(message);
        byte[] seed = new byte[16];
        random.nextBytes(seed);

        Pair<InstructionPacket, List<SubHeader>> pair = PolySphinxUtil.createPolySphinxPacketForTests(
                params,
                context.replicationNode,
                context.replication.pub(),
                context.suffixPaths,
                context.receivers,
                message,
                seed,
                context.keySets);
        InstructionPacket packet = pair.component1();
        byte[] raw = client.packInstructionPacket(packet);

        long replicationStart = System.nanoTime();
        List<InstructionPacketAndNextHop> replicationOutputs = context.replicationMix.processForTest(raw);
        double replicationDurationMicros = (System.nanoTime() - replicationStart) / 1_000.0;
        if (recordStats) {
            stats.computeIfAbsent(labelForStage(0, p), k -> new BenchmarkStats()).record(replicationDurationMicros);
        }

        Deque<QueueEntry> queue = new ArrayDeque<>();
        for (InstructionPacketAndNextHop out : replicationOutputs) {
            queue.add(new QueueEntry(out.getPacket(), out.getNextHop(), 1));
        }

        while (!queue.isEmpty()) {
            QueueEntry entry = queue.removeFirst();
            String nextHopKey = Base64.getEncoder().encodeToString(entry.nextHop);
            TestMixNode target = context.mixNodes.get(nextHopKey);
            if (target == null) {
                continue;
            }

            byte[] currPacket = client.packInstructionPacket(entry.packet);
            long start = System.nanoTime();
            List<InstructionPacketAndNextHop> outputs = target.processForTest(currPacket);
            double durationMicros = (System.nanoTime() - start) / 1_000.0;
            if (recordStats) {
                int stageLabel = context.exitNodeKeys.contains(nextHopKey) ? 2 : 1;
                stats.computeIfAbsent(labelForStage(stageLabel, p), k -> new BenchmarkStats())
                        .record(durationMicros);
            }

            for (InstructionPacketAndNextHop output : outputs) {
                queue.add(new QueueEntry(output.getPacket(), output.getNextHop(), entry.stage + 1));
            }
        }
    }

    private String labelForStage(int stage, int replicationCount) {
        if (stage == 0) {
            return "Replication p=" + replicationCount;
        }

        if (stage == 2) {
            return "Exit p=" + replicationCount;
        }
        return "Relay p=" + replicationCount;
    }
    private record QueueEntry(InstructionPacket packet, byte[] nextHop, int stage) { }

    private record PolySphinxContext(PkiEntry replication,
                                     byte[] replicationNode,
                                     List<byte[][]> suffixPaths,
                                     List<ECPoint[]> keySets,
                                     List<byte[]> receivers,
                                     Map<String, TestMixNode> mixNodes,
                                     List<String> exitNodeKeys,
                                     TestMixNode replicationMix) {
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