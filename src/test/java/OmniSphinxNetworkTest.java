import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.InstructionPacket.InstructionPacketAndNextHop;
import MasterThesisFormat.MixNode;
import MasterThesisFormat.Params;
import MasterThesisFormat.MixFormats.PolySphinx.PolySphinxUtil;
import MasterThesisFormat.MixFormats.PolySphinx.SubHeader;
import MasterThesisFormat.VM.VMException;
import MasterThesisFormat.pki.PkiEntry;
import MasterThesisFormat.pki.PkiGenerator;
import MasterThesisFormat.routing.RandomRoutingStrategy;
import kotlin.Pair;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

import static org.junit.Assert.*;

public class OmniSphinxNetworkTest {
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
            mixNodeIds[i] = ClientUtil.encodeNode(i + 1, 0);
            String url = "http://localhost:" + (9000 + i);
            mixNodes[i] = new TestNode(url.getBytes(StandardCharsets.UTF_8), mixNodePrivs[i], params);
            mixIdMap.put(Base64.getEncoder().encodeToString(mixNodeIds[i]), i);
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
            clientIdMap.put(Base64.getEncoder().encodeToString(clientIds[i]), i);
        }
    }

    @Test
    public void testOmniSphinxEmulatingSphinx() throws Exception {
        for (int p = 0; p < PACKET_COUNT; p++) {
            int senderIndex = random.nextInt(CLIENT_COUNT);
            Client sender = clients[senderIndex];

            int receiverIndex = randomDistinctIndices(CLIENT_COUNT, 1, senderIndex)[0];
            byte[] destination = clientIds[receiverIndex];

            int hopCount = 3 + random.nextInt(3); // at least three mix nodes
            int[] mixIndices = randomDistinctIndices(MIX_NODE_COUNT, hopCount, -1);
            byte[][] nodeList = new byte[hopCount][];
            ECPoint[] keyList = new ECPoint[hopCount];
            for (int i = 0; i < hopCount; i++) {
                nodeList[i] = mixNodeIds[mixIndices[i]];
                keyList[i] = mixNodePubs[mixIndices[i]];
            }

            InstructionPacket packet = sender.createSphinxInstructionPacket(nodeList, keyList, destination, "test".getBytes());
            byte[] raw = sender.packInstructionPacket(packet);
            InstructionPacket current = packet;
            byte[] nextHop = null;

            for (int i = 0; i < hopCount; i++) {
                TestNode node = mixNodes[mixIndices[i]];
                List<InstructionPacketAndNextHop> outs = node.processForTest(raw);
                assertEquals(1, outs.size());
                InstructionPacketAndNextHop res = outs.get(0);
                nextHop = res.getNextHop();
                current = res.getPacket();
                raw = sender.packInstructionPacket(current);
            }

            assertArrayEquals(destination, nextHop);

            byte[] finalPayload = current.getPayload();
            byte[] body = Arrays.copyOfRange(finalPayload, params.keyLength(), finalPayload.length);
            int padIndex = -1;
            for (int i = 0; i < body.length; i++) {
                if (body[i] == (byte) 0x7f) {
                    padIndex = i;
                    break;
                }
            }
            byte[] destMsg = Arrays.copyOf(body, padIndex);
            MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(destMsg);
            int arrLen = unpacker.unpackArrayHeader();
            assertEquals(2, arrLen);
            byte[] dest = unpacker.readPayload(unpacker.unpackBinaryHeader());
            byte[] msg = unpacker.readPayload(unpacker.unpackBinaryHeader());
            unpacker.close();

            assertArrayEquals(destination, dest);
            assertEquals("test", new String(msg));
        }
    }

    @Test
    public void testOmniSphinxEmulatingPolySphinx() throws Exception {
        for (int p = 0; p < PACKET_COUNT; p++) {
            int senderIndex = random.nextInt(CLIENT_COUNT);
            Client sender = clients[senderIndex];

            int receiverCount = 2;
            int[] receivers = randomDistinctIndices(CLIENT_COUNT, receiverCount, senderIndex);

            int replicationIndex = random.nextInt(MIX_NODE_COUNT);
            byte[] replicationNode = mixNodeIds[replicationIndex];
            ECPoint replicationPub = mixNodePubs[replicationIndex];

            List<byte[][]> suffixPaths = new ArrayList<>();
            List<ECPoint[]> keySets = new ArrayList<>();
            int[] exitIndices = randomDistinctIndices(MIX_NODE_COUNT, receiverCount, replicationIndex);
            Map<Integer, Integer> exitToReceiver = new HashMap<>();
            for (int r = 0; r < receiverCount; r++) {
                byte[][] path = new byte[][]{mixNodeIds[exitIndices[r]], clientIds[receivers[r]]};
                suffixPaths.add(path);
                ECPoint[] ks = new ECPoint[]{mixNodePubs[exitIndices[r]], clientPubs[receivers[r]]};
                keySets.add(ks);
                exitToReceiver.put(exitIndices[r], receivers[r]);
            }

            byte[] seed = new byte[16];
            random.nextBytes(seed);
            Pair<InstructionPacket, List<SubHeader>> pair = PolySphinxUtil.createPolySphinxPacketForTests(
                    params, replicationNode, replicationPub, suffixPaths, "test".getBytes(), seed, keySets);
            InstructionPacket packet = pair.component1();
            byte[] raw = sender.packInstructionPacket(packet);

            TestNode replicationNodeObj = mixNodes[replicationIndex];
            List<InstructionPacketAndNextHop> replicationOutputs = replicationNodeObj.processForTest(raw);
            assertEquals(receiverCount, replicationOutputs.size());

            for (InstructionPacketAndNextHop out : replicationOutputs) {
                String key = Base64.getEncoder().encodeToString(out.getNextHop());
                int exitIndex = mixIdMap.get(key);
                TestNode exitNode = mixNodes[exitIndex];

                List<InstructionPacketAndNextHop> exitOutputs =
                        exitNode.processForTest(sender.packInstructionPacket(out.getPacket()));
                assertEquals(1, exitOutputs.size());
                InstructionPacketAndNextHop finalPacket = exitOutputs.get(0);

                String destKey = Base64.getEncoder().encodeToString(finalPacket.getNextHop());
                int receiverIdx = clientIdMap.get(destKey);
                assertTrue(contains(receivers, receiverIdx));
                assertEquals("test", new String(finalPacket.getPacket().getPayload()));
            }
        }
    }
    private boolean contains(int[] arr, int value) {
        for (int v : arr) {
            if (v == value) return true;
        }
        return false;
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