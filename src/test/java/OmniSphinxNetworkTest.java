import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.InstructionPacket.InstructionPacketAndNextHop;
import MasterThesisFormat.MixFormats.MultiSphinx.MultiSphinxUtil;
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
    public void testOmniSphinxEmulatingSphinx() throws Exception {
        for (int p = 0; p < PACKET_COUNT; p++) {
            int senderIndex = random.nextInt(CLIENT_COUNT);
            Client sender = clients[senderIndex];

            System.out.println("Sender Index: " + senderIndex);

            int receiverIndex = randomDistinctIndices(CLIENT_COUNT, 1, senderIndex)[0];
            byte[] destination = clientIds[receiverIndex];

            System.out.println("Receiver Index: " + receiverIndex);
            int hopCount = 3 + random.nextInt(3); // at least three mix nodes
            int[] mixIndices = randomDistinctIndices(MIX_NODE_COUNT, hopCount, -1);

            for (int i = 0; i < mixIndices.length; i++) {
                System.out.println(i + "te Mix Node Index: " + mixIndices[i]);
            }
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
                System.out.println(i + "te Mix Node hat die Onion verarbeitet mit Index: " + mixIndices[i]);
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
            assertEquals(1, arrLen);
            byte[] msg = unpacker.readPayload(unpacker.unpackBinaryHeader());
            unpacker.close();

            assertEquals("test", new String(msg));
        }
    }

    @Test
    public void testOmniSphinxEmulatingPolySphinx() throws Exception {
        for (int p = 0; p < PACKET_COUNT; p++) {
            int senderIndex = random.nextInt(CLIENT_COUNT);
            Client sender = clients[senderIndex];


            int receiverCount = 5;
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

            byte[] seed = new byte[16];
            random.nextBytes(seed);
            InstructionPacket packet = PolySphinxUtil.createPolySphinxPacket(
                    params, replicationNode, replicationPub, suffixPaths, receiversList,"test".getBytes(), seed, keySets);
            byte[] raw = sender.packInstructionPacket(packet);

            TestNode replicationNodeObj = mixNodes[replicationIndex];
            List<InstructionPacketAndNextHop> replicationOutputs = replicationNodeObj.processForTest(raw);
            assertEquals(receiverCount, replicationOutputs.size());

            Deque<InstructionPacketAndNextHop> queue = new ArrayDeque<>(replicationOutputs);

            while (!queue.isEmpty()) {
                InstructionPacketAndNextHop currentOut = queue.removeFirst();
                String hopKey = Base64.getEncoder().encodeToString(currentOut.getNextHop());
                Integer mixIndex = mixIdMap.get(hopKey);

                if (mixIndex != null) {
                    TestNode mixNode = mixNodes[mixIndex];
                    byte[] packed = sender.packInstructionPacket(currentOut.getPacket());
                    List<InstructionPacketAndNextHop> outputs = mixNode.processForTest(packed);
                    assertFalse("Mix node produced no outputs", outputs.isEmpty());
                    queue.addAll(outputs);
                } else {

                    Integer receiverIdx = clientIdMap.get(hopKey);
                    assertNotNull("Unknown recipient for key " + hopKey, receiverIdx);
                    assertTrue(contains(receivers, receiverIdx));
                    assertEquals("test", new String(currentOut.getPacket().getPayload()));
                }
            }
        }
    }


    @Test
    public void testOmniSphinxEmulatingMultiSphinx() throws Exception {
        for (int p = 0; p < PACKET_COUNT; p++) {
            int senderIndex = random.nextInt(CLIENT_COUNT);
            Client sender = clients[senderIndex];

            int prefixHops = 2;
            int[] prefixIndices = randomDistinctIndices(MIX_NODE_COUNT, prefixHops, -1);
            byte[][] prefixNodes = new byte[prefixHops][];
            ECPoint[] prefixKeys = new ECPoint[prefixHops];
            for (int i = 0; i < prefixHops; i++) {
                prefixNodes[i] = mixNodeIds[prefixIndices[i]];
                prefixKeys[i] = mixNodePubs[prefixIndices[i]];
            }

            int subPacketCount = 2;
            int suffixHops = 2;
            List<byte[][]> suffixPaths = new ArrayList<>();
            List<ECPoint[]> suffixKeys = new ArrayList<>();
            byte[][] messages = new byte[subPacketCount][];
            byte[][] destinations = new byte[subPacketCount][];
            Map<String, String> expectedMessages = new HashMap<>();

            for (int i = 0; i < subPacketCount; i++) {
                int[] receiverArray = randomDistinctIndices(CLIENT_COUNT, 1, senderIndex);
                int receiverIndex = receiverArray[0];
                byte[] destination = Arrays.copyOf(clientIds[receiverIndex], params.keyLength());
                destinations[i] = destination;

                int[] mixIndices = randomDistinctIndices(MIX_NODE_COUNT, suffixHops, -1);
                byte[][] path = new byte[suffixHops][];
                ECPoint[] keyList = new ECPoint[suffixHops];
                for (int h = 0; h < suffixHops; h++) {
                    path[h] = mixNodeIds[mixIndices[h]];
                    keyList[h] = mixNodePubs[mixIndices[h]];
                }
                suffixPaths.add(path);
                suffixKeys.add(keyList);

                messages[i] = ("message-" + i).getBytes(StandardCharsets.UTF_8);
                expectedMessages.put(Base64.getEncoder().encodeToString(destination), new String(messages[i]));
            }

            InstructionPacket packet = MultiSphinxUtil.createMultiSphinxPacket(
                    params, prefixNodes, prefixKeys, suffixPaths, suffixKeys, messages, destinations);

            byte[] raw = sender.packInstructionPacket(packet);
            Deque<InstructionPacketAndNextHop> queue = new ArrayDeque<>();

            for (int hop = 0; hop < prefixHops; hop++) {
                TestNode node = mixNodes[prefixIndices[hop]];
                List<InstructionPacketAndNextHop> outs = node.processForTest(raw);
                if (hop < prefixHops - 1) {
                    assertEquals(1, outs.size());
                    InstructionPacketAndNextHop out = outs.get(0);
                    raw = sender.packInstructionPacket(out.getPacket());
                } else {
                    assertEquals(subPacketCount, outs.size());
                    queue.addAll(outs);
                }
            }

            while (!queue.isEmpty()) {
                InstructionPacketAndNextHop currentOut = queue.removeFirst();
                String hopKey = Base64.getEncoder().encodeToString(currentOut.getNextHop());
                Integer mixIndex = mixIdMap.get(hopKey);

                if (mixIndex != null) {
                    TestNode mixNode = mixNodes[mixIndex];
                    byte[] packed = sender.packInstructionPacket(currentOut.getPacket());
                    List<InstructionPacketAndNextHop> outputs = mixNode.processForTest(packed);
                    assertFalse(outputs.isEmpty());
                    queue.addAll(outputs);
                } else {
                    Integer receiverIdx = clientIdMap.get(hopKey);
                    assertNotNull("Unknown recipient for key " + hopKey, receiverIdx);
                    String expected = expectedMessages.get(hopKey);
                    assertNotNull("Missing expected message for receiver" + hopKey, expected);
                    assertEquals(expected, extractMessage(currentOut.getPacket()));
                }
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

        public TestNode(byte[] id, BigInteger secret, Params params) throws IOException {
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

    private String extractMessage(InstructionPacket packet) throws IOException {
        byte[] body = packet.getPayload();
        int padIndex = -1;
        for (int i = 0; i < body.length; i++) {
            if (body[i] == (byte) 0x7f) {
                padIndex = i;
                break;
            }
        }
        assertTrue("Padding delimiter not found", padIndex > 0);
        byte[] destMsg = Arrays.copyOf(body, padIndex);
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(destMsg);
        int arrLen = unpacker.unpackArrayHeader();
        assertEquals(1, arrLen);
        byte[] msg = unpacker.readPayload(unpacker.unpackBinaryHeader());
        unpacker.close();
        return new String(msg);
    }
}