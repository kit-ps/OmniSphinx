package OmniSphinx.benchmarks;

import OmniSphinx.Client;
import OmniSphinx.ClientUtil;
import OmniSphinx.InstructionPacket.InstructionPacket;
import OmniSphinx.InstructionPacket.InstructionPacketAndNextHop;
import OmniSphinx.MixFormats.MultiSphinx.MultiSphinxUtil;
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
public class MultiSphinxPackageCreationBenchmark {
    private static final int MIX_NODE_COUNT = 100;
    private static final int CLIENT_COUNT = 30;
    private static final int SUB_PACKET_COUNT = 10;

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

    byte[][] prefixNodes;
    ECPoint[] prefixKeys;
    List<byte[][]> suffixPaths;
    List<ECPoint[]> suffixKeys;
    byte[][] destinations;
    byte[][] messages;

    @Setup
    public void setUp() throws Exception {
        params = new Params(16, 53221, 19200, new ECCGroup(), 5000);
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
    }

    @Setup(Level.Invocation)
    public void setupInvocation() throws Exception {
        int prefixHops = 3;
        int suffixHops = 3;

        int senderIndex = random.nextInt(CLIENT_COUNT);
        Client sender = clients[senderIndex];

        int[] prefixIndices = randomDistinctIndices(MIX_NODE_COUNT, prefixHops, -1);
        prefixNodes = new byte[prefixHops][];
        prefixKeys = new ECPoint[prefixHops];
        for (int h = 0; h < prefixHops; h++) {
            prefixNodes[h] = mixNodeIds[prefixIndices[h]];
            prefixKeys[h] = mixNodePubs[prefixIndices[h]];
        }

        suffixPaths = new ArrayList<>();
        suffixKeys = new ArrayList<>();
        destinations = new byte[SUB_PACKET_COUNT][];
        messages = new byte[SUB_PACKET_COUNT][];

        for (int p = 0; p < SUB_PACKET_COUNT; p++) {
            int receiverIndex = randomDistinctIndices(CLIENT_COUNT, 1, senderIndex)[0];
            destinations[p] = Arrays.copyOf(clientIds[receiverIndex], params.keyLength());

            int[] mixIndices = randomDistinctIndices(MIX_NODE_COUNT, suffixHops, -1);
            byte[][] path = new byte[suffixHops][];
            ECPoint[] keyList = new ECPoint[suffixHops];
            for (int h = 0; h < suffixHops; h++) {
                path[h] = mixNodeIds[mixIndices[h]];
                keyList[h] = mixNodePubs[mixIndices[h]];
            }
            suffixPaths.add(path);
            suffixKeys.add(keyList);

            byte[] message = new byte[256];
            random.nextBytes(message);
            messages[p] = message;
        }
    }

    @Benchmark
    public InstructionPacket multiSphinxCreation() throws Exception {
        return MultiSphinxUtil.createMultiSphinxPacket(
                    params, prefixNodes, prefixKeys, suffixPaths, suffixKeys, messages, destinations);
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
            .include(MultiSphinxPackageCreationBenchmark.class.getSimpleName())
            .forks(1)
            .resultFormat(ResultFormatType.JSON)
            .result(Path.of("target", "benchmarks", "multisphinx-creation.json").toString())
            .build();

        new Runner(opt).run();
    }
}
