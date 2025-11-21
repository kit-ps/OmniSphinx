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
            Map<String, BenchmarkStats> stageStats = new LinkedHashMap<>();

            for (int warmup = 0; warmup < WARMUP_RUNS; warmup++) {
                runPath(context, p, stageStats, false);
            }
            for (int run = 0; run < RUNS; run++) {
                runPath(context, p, stageStats, true);
            }

            assertHasDataForStage("Replication", p, stageStats);
            assertHasDataForStage("Relay", p, stageStats);
            assertHasDataForStage("Exit", p, stageStats);
            reportStageBenchmarks(p, stageStats);
        }
    }

    private PolySphinxContext prepareContext(int replicationCount) throws Exception {
        PkiEntry replication = generator.generateKeyPair();
        byte[] replicationNode = ClientUtil.encodeNode(10, 0);

        List<byte[][]> suffixPaths = new ArrayList<>();
        List<ECPoint[]> keySets = new ArrayList<>();
        List<byte[]> receivers = new ArrayList<>();
        Map<String, TestMixNode> mixNodes = new LinkedHashMap<>();

        for (int i = 0; i < replicationCount; i++) {
            List<byte[]> pathNodes = new ArrayList<>();
            List<ECPoint> keys = new ArrayList<>();

            PkiEntry relay = generator.generateKeyPair();
            byte[] relayNode = ClientUtil.encodeNode(20 + (i * 10), 0);
            pathNodes.add(relayNode);
            keys.add(relay.pub());
            mixNodes.put(Base64.getEncoder().encodeToString(Arrays.copyOf(relayNode, params.keyLength())),
                    new TestMixNode("http://relay-" + i, relay.priv(), params));


            PkiEntry exit = generator.generateKeyPair();
            byte[] exitNode = ClientUtil.encodeNode(21 + (i * 10), 0);
            pathNodes.add(exitNode);
            keys.add(exit.pub());
            mixNodes.put(Base64.getEncoder().encodeToString(Arrays.copyOf(exitNode, params.keyLength())),
                    new TestMixNode("http://exit-" + i, exit.priv(), params));

            suffixPaths.add(pathNodes.toArray(new byte[0][]));
            keySets.add(keys.toArray(new ECPoint[0]));
            receivers.add(Arrays.copyOf(ClientUtil.encodeNode(1001 + i, 0), params.keyLength()));
        }


        TestMixNode replicationMix = new TestMixNode("http://replication", replication.priv(), params);

        return new PolySphinxContext(replication, replicationNode, suffixPaths, keySets, receivers, mixNodes, replicationMix);
    }

    private void runPath(PolySphinxContext context, int p, Map<String, BenchmarkStats> statsByStage, boolean recordStats) throws Exception {        byte[] message = new byte[32 + random.nextInt(32)];
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

        TestMixNode replication = context.replicationMix();
        //Replication
        long replicationStart = System.nanoTime();
        List<InstructionPacketAndNextHop> replicationOutputs = replication.processForTest(raw);
        double replicationDurationMicros = (System.nanoTime() - replicationStart) / 1_000.0;
        if (recordStats) {
            statsByStage.computeIfAbsent(labelForStage(0, p), k -> new BenchmarkStats())
                    .record(replicationDurationMicros);
        }

        //Relay
        List<InstructionPacketAndNextHop> relayOutputs = new ArrayList<>();
        for (InstructionPacketAndNextHop replicationOutput : replicationOutputs) {
            TestMixNode relayNode = context.mixNodes.get(Base64.getEncoder().encodeToString(replicationOutput.getNextHop()));
            if (relayNode == null) {
                System.out.println("RelayNode not found?!");
                continue;
            }

            byte[] relayPacket = client.packInstructionPacket(replicationOutput.getPacket());
            long relayStart = System.nanoTime();
            List<InstructionPacketAndNextHop> outputs = relayNode.processForTest(relayPacket);
            double relayDurationMicros = (System.nanoTime() - relayStart) / 1_000.0;
            if (recordStats) {
                statsByStage.computeIfAbsent(labelForStage(1, p), k -> new BenchmarkStats())
                        .record(relayDurationMicros);
            }
            relayOutputs.addAll(outputs);
        }

        //Exit
        for (InstructionPacketAndNextHop relayOutput : relayOutputs) {
            TestMixNode exitNode = context.mixNodes.get(Base64.getEncoder().encodeToString(relayOutput.getNextHop()));
            if (exitNode == null) {
                System.out.println("ExitNode not found?!");
                continue;
            }

            byte[] exitPacket = client.packInstructionPacket(relayOutput.getPacket());
            long exitStart = System.nanoTime();
            exitNode.processForTest(exitPacket);
            double exitDurationMicros = (System.nanoTime() - exitStart) / 1_000.0;
            if (recordStats) {
                statsByStage.computeIfAbsent(labelForStage(2, p), k -> new BenchmarkStats())
                        .record(exitDurationMicros);
            }
        }
    }

    private void reportStageBenchmarks(int p, Map<String, BenchmarkStats> stats) throws Exception {
        reportSingleStage("Replication", p, stats);
        reportSingleStage("Relay", p, stats);
        reportSingleStage("Exit", p, stats);
    }

    private void reportSingleStage(String stage, int p, Map<String, BenchmarkStats> stats) throws Exception {
        String label = labelForStageName(stage, p);
        BenchmarkStats stageStats = stats.get(label);
        if (stageStats == null) {
            System.out.printf("No stats recorded for %s%n", label);
            return;
        }

        Map<String, BenchmarkStats> stageMap = Map.of(label, stageStats);
        String title = "PolySphinx " + stage + " p=" + p;
        BenchmarkReporter.printStats(title, stageMap);
        BenchmarkReporter.plotViolin(title, stageMap, "polysphinx-" + stage.toLowerCase() + "-p" + p + ".pdf");
    }

    private String labelForStage(int stage, int replicationCount) {
        if (stage == 0) {
            return labelForStageName("Replication", replicationCount);
        }

        if (stage == 2) {
            return labelForStageName("Exit", replicationCount);
        }
        return labelForStageName("Relay", replicationCount);
    }

    private void assertHasDataForStage(String stage, int replicationCount, Map<String, BenchmarkStats> stats) {
        String label = labelForStageName(stage, replicationCount);
        BenchmarkStats stageStats = stats.get(label);
        assertTrue("No stats recorded for " + label, stageStats != null && stageStats.getCount() > 0);
    }

    private String labelForStageName(String stage, int replicationCount) {
        return stage + " p=" + replicationCount;
    }


    private record PolySphinxContext(PkiEntry replication,
                                     byte[] replicationNode,
                                     List<byte[][]> suffixPaths,
                                     List<ECPoint[]> keySets,
                                     List<byte[]> receivers,
                                     Map<String, TestMixNode> mixNodes,
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