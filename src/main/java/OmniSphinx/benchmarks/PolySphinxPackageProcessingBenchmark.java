package OmniSphinx.benchmarks;

import OmniSphinx.Client;
import OmniSphinx.ClientUtil;
import OmniSphinx.InstructionPacket.InstructionPacket;
import OmniSphinx.InstructionPacket.InstructionPacketAndNextHop;
import OmniSphinx.MixFormats.PolySphinx.PolySphinxUtil;
import OmniSphinx.MixFormats.PolySphinx.SubHeader;
import OmniSphinx.MixNode;
import OmniSphinx.Params;
import OmniSphinx.crypto.ECCGroup;
import OmniSphinx.pki.PkiEntry;
import OmniSphinx.pki.PkiGenerator;
import OmniSphinx.routing.RandomRoutingStrategy;
import kotlin.Pair;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
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
public class PolySphinxPackageProcessingBenchmark {
    @Param({"3", "5", "10"})
    public int p_value;

    private Params params;
    private Client client;
    private PkiGenerator generator;
    private final SecureRandom random = new SecureRandom();
    private PolySphinxContext context;

    byte[] packetReplication;
    byte[] packetRelay;
    byte[] packetExit;
    TestMixNode nodeRelay;
    TestMixNode nodeExit;

    @Setup
    public void setUp() throws Exception {
        int instructionLength = switch (p_value) {
            case 3 -> 694;
            case 5 -> 1132;
            case 10 -> 2227;
            default -> throw new IllegalStateException("No value known for given p");
        };
        params = new Params(16, 1024, 0, new ECCGroup(), instructionLength);
        client = new Client(params, new RandomRoutingStrategy());
        generator = new PkiGenerator(params);
        context = prepareContext(p_value);
    }

    @Setup(Level.Invocation)
    public void setupInvocation() throws Exception {
        byte[] message = new byte[1024];
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
        packetReplication = raw;

        TestMixNode replication = context.replicationMix();
        //Replication
        List<InstructionPacketAndNextHop> replicationOutputs;
        replicationOutputs = replication.processForTest(raw);

        //Relay
        List<InstructionPacketAndNextHop> relayOutputs = new ArrayList<>();
        for (InstructionPacketAndNextHop replicationOutput : replicationOutputs) {
            TestMixNode relayNode = context.mixNodes.get(Base64.getEncoder().encodeToString(replicationOutput.getNextHop()));
            if (relayNode == null) {
                System.out.println("RelayNode not found?!");
                continue;
            }

            byte[] relayPacket = client.packInstructionPacket(replicationOutput.getPacket());
            packetRelay = relayPacket;
            nodeRelay = relayNode;
            List<InstructionPacketAndNextHop> outputs;
            outputs = relayNode.processForTest(relayPacket);
            relayOutputs.addAll(outputs);
            break;
        }

        //Exit
        for (InstructionPacketAndNextHop relayOutput : relayOutputs) {
            TestMixNode exitNode = context.mixNodes.get(Base64.getEncoder().encodeToString(relayOutput.getNextHop()));
            if (exitNode == null) {
                System.out.println("ExitNode not found?!");
                continue;
            }

            byte[] exitPacket = client.packInstructionPacket(relayOutput.getPacket());
            packetExit = exitPacket;
            nodeExit = exitNode;
        }
    }

    @Benchmark
    public List<InstructionPacketAndNextHop> replication() throws Exception {
        return context.replicationMix().processForTest(packetReplication);
    }

    @Benchmark
    public List<InstructionPacketAndNextHop> relay() throws Exception {
        return nodeRelay.processForTest(packetRelay);
    }

    @Benchmark
    public List<InstructionPacketAndNextHop> exit() throws Exception {
        return nodeExit.processForTest(packetExit);
    }

    private PolySphinxContext prepareContext(int replicationCount) throws Exception {
        PkiEntry replication = generator.generateKeyPair();
        byte[] replicationNode = Arrays.copyOf(ClientUtil.encodeNode(10, 0), params.keyLength());

        List<byte[][]> suffixPaths = new ArrayList<>();
        List<ECPoint[]> keySets = new ArrayList<>();
        List<byte[]> receivers = new ArrayList<>();
        Map<String, TestMixNode> mixNodes = new LinkedHashMap<>();

        for (int i = 0; i < replicationCount; i++) {
            List<byte[]> pathNodes = new ArrayList<>();
            List<ECPoint> keys = new ArrayList<>();

            PkiEntry relay = generator.generateKeyPair();
            byte[] relayNode = Arrays.copyOf(ClientUtil.encodeNode(20 + (i * 10), 0), params.keyLength());
            pathNodes.add(relayNode);
            keys.add(relay.pub());
            mixNodes.put(Base64.getEncoder().encodeToString(Arrays.copyOf(relayNode, params.keyLength())),
                    new TestMixNode("http://relay-" + i, relay.priv(), params));


            PkiEntry exit = generator.generateKeyPair();
            byte[] exitNode = Arrays.copyOf(ClientUtil.encodeNode(21 + (i * 10), 0), params.keyLength());
            pathNodes.add(exitNode);
            keys.add(exit.pub());
            mixNodes.put(Base64.getEncoder().encodeToString(exitNode),
                    new TestMixNode("http://exit-" + i, exit.priv(), params));

            suffixPaths.add(pathNodes.toArray(new byte[0][]));
            keySets.add(keys.toArray(new ECPoint[0]));
            receivers.add(Arrays.copyOf(ClientUtil.encodeNode(1001 + i, 0), params.keyLength()));
        }


        TestMixNode replicationMix = new TestMixNode("http://replication", replication.priv(), params);

        return new PolySphinxContext(replication, replicationNode, suffixPaths, keySets, receivers, mixNodes, replicationMix);
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

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(PolySphinxPackageProcessingBenchmark.class.getSimpleName())
            .forks(1)
            .resultFormat(ResultFormatType.JSON)
            .result(Path.of("target", "benchmarks", "polysphinx-processing.json").toString())
            .build();

        new Runner(opt).run();
    }
}
