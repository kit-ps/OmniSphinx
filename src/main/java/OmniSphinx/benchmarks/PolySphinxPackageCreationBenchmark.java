package OmniSphinx.benchmarks;

import OmniSphinx.Client;
import OmniSphinx.ClientUtil;
import OmniSphinx.InstructionPacket.InstructionPacket;
import OmniSphinx.InstructionPacket.InstructionPacketAndNextHop;
import OmniSphinx.MixFormats.PolySphinx.PolySphinxUtil;
import OmniSphinx.MixNode;
import OmniSphinx.Params;
import OmniSphinx.VM.VMException;
import OmniSphinx.crypto.ECCGroup;
import OmniSphinx.pki.PkiEntry;
import OmniSphinx.pki.PkiGenerator;
import OmniSphinx.routing.RandomRoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@BenchmarkMode(Mode.SampleTime)
@State(Scope.Benchmark)
public class PolySphinxPackageCreationBenchmark {
    @Param({"3", "5", "10"})
    int replicationFactor;

    private static final int MIX_NODE_COUNT = 100;
    private static final int CLIENT_COUNT = 30;

    private Params params;
    private byte[][] mixNodeIds;
    private ECPoint[] mixNodePubs;
    private BigInteger[] mixNodePrivs;
    private TestNode[] mixNodes;
    private Map<String, Integer> mixIdMap;

    private byte[][] clientIds;
    private ECPoint[] clientPubs;
    private Map<String, Integer> clientIdMap;
    private Client[] clients;
    private final SecureRandom random = new SecureRandom();

    byte[] replicationNode;
    ECPoint replicationPub;
    List<byte[][]> suffixPaths;
    List<byte[]> receiversList;
    List<ECPoint[]> keySets;
    byte[] seed;

    @Setup
    public void setUp() throws Exception {
        params = new Params(16, 0, 0, new ECCGroup(), 2847);
        PkiGenerator generator = new PkiGenerator(params);

        mixNodeIds = new byte[MIX_NODE_COUNT][];
        mixNodePubs = new ECPoint[MIX_NODE_COUNT];
        mixNodePrivs = new BigInteger[MIX_NODE_COUNT];
        mixNodes = new TestNode[MIX_NODE_COUNT];
        mixIdMap = new HashMap<>();

        for (int i = 0; i < MIX_NODE_COUNT; i++) {
            PkiEntry entry = generator.generateKeyPair();
            mixNodePubs[i] = entry.pub();
            mixNodePrivs[i] = entry.priv();
            mixNodeIds[i] = Arrays.copyOf(ClientUtil.encodeNode(i + 1, 0), params.keyLength());
            String url = "http://localhost:" + (9000 + i);
            mixNodes[i] = new TestNode(url.getBytes(StandardCharsets.UTF_8), mixNodePrivs[i], params);
            byte[] truncatedId = Arrays.copyOf(mixNodeIds[i], params.keyLength());
            mixIdMap.put(Base64.getEncoder().encodeToString(truncatedId), i);
        }

        clients = new Client[CLIENT_COUNT];
        clientIds = new byte[CLIENT_COUNT][];
        clientPubs = new ECPoint[CLIENT_COUNT];
        clientIdMap = new HashMap<>();
        for (int i = 0; i < CLIENT_COUNT; i++) {
            PkiEntry entry = generator.generateKeyPair();
            clientIds[i] = ClientUtil.encodeNode(1000 + i, 0);
            clientPubs[i] = entry.pub();
            clients[i] = new Client(params, new RandomRoutingStrategy());
            byte[] truncatedId = Arrays.copyOf(clientIds[i], params.keyLength());
            clientIdMap.put(Base64.getEncoder().encodeToString(truncatedId), i);
        }

        int senderIndex = random.nextInt(CLIENT_COUNT);
        Client sender = clients[senderIndex];


        int[] receivers = randomDistinctIndices(CLIENT_COUNT, replicationFactor, senderIndex);

        int replicationIndex =  random.nextInt(MIX_NODE_COUNT);
        replicationNode = mixNodeIds[replicationIndex];
        replicationPub = mixNodePubs[replicationIndex];

        suffixPaths = new ArrayList<>();
        receiversList = new ArrayList<>();
        keySets = new ArrayList<>();
        int hopCount = 3;

        //create Suffixpaths
        for (int r = 0; r < replicationFactor; r++) {
            int receiverIndex = receivers[r];
            int[] mixIndices = randomDistinctIndices(MIX_NODE_COUNT, hopCount, -1);
            byte[][] nodeList = new byte[hopCount][];
            ECPoint[] keyList = new ECPoint[hopCount];
            for (int i = 0; i < hopCount; i++) {
                nodeList[i] = mixNodeIds[mixIndices[i]];
                keyList[i] = mixNodePubs[mixIndices[i]];
            }
            suffixPaths.add(nodeList);
            receiversList.add(Arrays.copyOf(clientIds[receiverIndex], params.keyLength()));
            keySets.add(keyList);
        }
    }

    @Setup(Level.Invocation)
    public void setupInvocation() throws Exception {
        seed = new byte[16];
        random.nextBytes(seed);
    }

    @Benchmark
    public InstructionPacket polySphinxCreation() throws Exception {
        return PolySphinxUtil.createPolySphinxPacket(params, replicationNode, replicationPub, suffixPaths, receiversList,"test".getBytes(), seed, keySets);
    }

    private int[] randomDistinctIndices(int max, int count, int exclude) {
        List<Integer> list = new ArrayList<>();
        for (int i = 0; i < max; i++) {
            if (i != exclude) {
                list.add(i);
            }
        }
        Collections.shuffle(list, random);
        int[] result = new int[count];
        for (int i = 0; i < count; i++) {
            result[i] = list.get(i);
        }
        return result;
    }

    private static class TestNode extends MixNode {
        private final List<InstructionPacketAndNextHop> forwarded = new ArrayList<>();

        protected TestNode(byte[] id, BigInteger secret, Params params) throws IOException {
            super(id, secret, params);
        }

        @Override
        public void startListener(int port) {
            // no network listener during tests
        }

        @Override
        protected void sendToNextNode(byte[] nextHop, InstructionPacket packet) {
            forwarded.add(new InstructionPacketAndNextHop(nextHop, packet));
        }

        public List<InstructionPacketAndNextHop> processForTest(byte[] rawPacket) throws VMException {
            forwarded.clear();
            super.process(rawPacket);
            return new ArrayList<>(forwarded);
        }
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include(PolySphinxPackageCreationBenchmark.class.getSimpleName())
            .forks(1)
            .resultFormat(ResultFormatType.JSON)
            .result(Path.of("target", "benchmarks", "polysphinx-creation.json").toString())
            .build();

        new Runner(opt).run();
    }
}
