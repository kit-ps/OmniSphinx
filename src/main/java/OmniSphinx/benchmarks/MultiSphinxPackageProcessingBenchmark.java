package OmniSphinx.benchmarks;

import OmniSphinx.Client;
import OmniSphinx.ClientUtil;
import OmniSphinx.InstructionPacket.InstructionPacket;
import OmniSphinx.InstructionPacket.InstructionPacketAndNextHop;
import OmniSphinx.MixFormats.MultiSphinx.MultiSphinxUtil;
import OmniSphinx.MixNode;
import OmniSphinx.Params;
import OmniSphinx.crypto.ECCGroup;
import OmniSphinx.pki.PkiEntry;
import OmniSphinx.pki.PkiGenerator;
import OmniSphinx.routing.RandomRoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.nio.file.Path;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@BenchmarkMode(Mode.SampleTime)
@State(Scope.Benchmark)
public class MultiSphinxPackageProcessingBenchmark {
    @Param({"3", "5", "10"})
    public int p_value;

    private Params params;
    private Client client;
    private PkiGenerator generator;
    private final SecureRandom random = new SecureRandom();
    private MultiSphinxContext context;
    private byte[] packetRelay;
    private byte[] packetReplication;
    private TestMixNode nodeRelay;

    @Setup
    public void setUp() throws Exception {
        int payloadSize = switch (p_value) {
            case 3 -> 15268;
            case 5 -> 25446;
            case 10 -> 50891;
            default -> throw new IllegalStateException("no payload size known");
        };
        params = new Params(16, payloadSize, 0, new ECCGroup(), 112);
        client = new Client(params, new RandomRoutingStrategy());
        generator = new PkiGenerator(params);
        context = prepareContext(p_value);
    }

    @Setup(Level.Invocation)
    public void setupInvocation() throws Exception {
        int prefixHopCount = context.prefixHopCount;
        int suffixHopCount = context.suffixHopCount;
        byte[][] messages = new byte[p_value][];
        for (int i = 0; i < p_value; i++) {
            byte[] message = new byte[24];
            random.nextBytes(message);
            messages[i] = message;
        }

        InstructionPacket packet = MultiSphinxUtil.createMultiSphinxPacket(
                params, context.prefixNodeIds, context.prefixNodeKeys, context.suffixPaths, context.suffixKeys, messages, context.destinations);
        byte[] raw = client.packInstructionPacket(packet);
        packetReplication = raw;

        List<InstructionPacketAndNextHop> replicationOutputs = null;
        for (int hop = 0; hop < prefixHopCount; hop++) {
            TestMixNode node = context.prefixMixNodes[hop];
            replicationOutputs = node.processForTest(raw);

            if (hop < prefixHopCount - 1) {
                raw = client.packInstructionPacket(replicationOutputs.get(0).getPacket());
            }
        }

        assert replicationOutputs.size() == p_value;

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
            byte[] rawpacket = client.packInstructionPacket(entry.packet);
            packetRelay = rawpacket;
            nodeRelay = target;
            break;
        }
    }

    @Benchmark
    public List<InstructionPacketAndNextHop> replication() throws Exception {
        TestMixNode node = context.prefixMixNodes[0];
        return node.processForTest(packetReplication);
    }

    @Benchmark
    public List<InstructionPacketAndNextHop> relay() throws Exception {
        return nodeRelay.processForTest(packetRelay);
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

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(MultiSphinxPackageProcessingBenchmark.class.getSimpleName())
            .forks(1)
            .resultFormat(ResultFormatType.JSON)
            .result(Path.of("target", "benchmarks", "multisphinx-processing.json").toString())
            .build();

        new Runner(opt).run();
    }
}
