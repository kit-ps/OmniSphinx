package microBenchmarks;

import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.InstructionPacket.InstructionPacketAndNextHop;
import MasterThesisFormat.MixFormats.PolySphinx.PolySphinxUtil;
import MasterThesisFormat.MixNode;
import MasterThesisFormat.Params;
import MasterThesisFormat.VM.VMException;
import MasterThesisFormat.pki.PkiEntry;
import MasterThesisFormat.pki.PkiGenerator;
import MasterThesisFormat.routing.RandomRoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

import static org.junit.Assert.assertTrue;

public class PolySphinxPackageCreationBenchmark {
    private static final int RUNS = 100;

    private static final int MIX_NODE_COUNT = 100;
    private static final int CLIENT_COUNT = 30;
    private static final int PACKET_COUNT = 5;

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

    @Before
    public void setUp() throws Exception {
        params = new Params();
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

    @Test
    public void benchmarkPolySphinxPackageCreation() throws Exception {
        int senderIndex = random.nextInt(CLIENT_COUNT);
        Client sender = clients[senderIndex];


        int receiverCount = 10;
        int[] receivers = randomDistinctIndices(CLIENT_COUNT, receiverCount, senderIndex);

        int replicationIndex =  random.nextInt(MIX_NODE_COUNT);
        byte[] replicationNode = mixNodeIds[replicationIndex];
        ECPoint replicationPub = mixNodePubs[replicationIndex];

        List<byte[][]> suffixPaths = new ArrayList<>();
        List<byte[]> receiversList = new ArrayList<>();
        List<ECPoint[]> keySets = new ArrayList<>();
        int hopCount = 3;

        //create Suffixpaths
        for (int r = 0; r < receiverCount; r++) {
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

        BenchmarkStats creationStats = new BenchmarkStats();

        for (int i = 0; i < RUNS; i++) {
            byte[] message = new byte[32 + random.nextInt(32)];
            random.nextBytes(message);


            long start = System.nanoTime();
            byte[] seed = new byte[16];
            random.nextBytes(seed);
            InstructionPacket packet = PolySphinxUtil.createPolySphinxPacket(params, replicationNode, replicationPub, suffixPaths, receiversList,"test".getBytes(), seed, keySets);
            long duration = System.nanoTime() - start;
            double durationMs = duration / 1_000_000.0;
            creationStats.record(durationMs);
            packet.getPayload();
        }

        System.out.printf("PolySphinx creation avg ms: %.2f (min=%.2f, max=%.2f)%n",
                creationStats.getAverage(), creationStats.getMin(), creationStats.getMax());

        assertTrue(creationStats.getCount() > 0);
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

}
