import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.Params;
import MasterThesisFormat.MixFormats.PolySphinx.PolySphinxUtil;
import MasterThesisFormat.MixFormats.PolySphinx.SubHeader;
import MasterThesisFormat.pki.PkiEntry;
import MasterThesisFormat.pki.PkiGenerator;
import MasterThesisFormat.routing.RandomRoutingStrategy;
import kotlin.Pair;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertNotNull;

public class OmniSphinxNetworkTest {
    private static final int MIX_NODE_COUNT = 100;
    private static final int CLIENT_COUNT = 30;
    private static final int PACKET_COUNT = 5;

    private Params params;
    private byte[][] mixNodeIds;
    private ECPoint[] mixNodePubs;
    private byte[][] clientIds;
    private ECPoint[] clientPubs;
    private Client[] clients;
    private final SecureRandom random = new SecureRandom();

    @Before
    public void setUp() throws Exception {
        params = new Params();
        PkiGenerator generator = new PkiGenerator(params);

        mixNodeIds = new byte[MIX_NODE_COUNT][];
        mixNodePubs = new ECPoint[MIX_NODE_COUNT];
        for (int i = 0; i < MIX_NODE_COUNT; i++) {
            PkiEntry entry = generator.generateKeyPair();
            mixNodePubs[i] = entry.pub();
            mixNodeIds[i] = ClientUtil.encodeNode(i + 1, 0);
        }

        clients = new Client[CLIENT_COUNT];
        clientIds = new byte[CLIENT_COUNT][];
        clientPubs = new ECPoint[CLIENT_COUNT];
        for (int i = 0; i < CLIENT_COUNT; i++) {
            PkiEntry entry = generator.generateKeyPair();
            clientIds[i] = ClientUtil.encodeNode(1000 + i, 0);
            clientPubs[i] = entry.pub();
            clients[i] = new Client(params, new RandomRoutingStrategy());
        }
    }

    @Test
    public void testRandomOmniSphinxTraffic() throws Exception {
        for (int p = 0; p < PACKET_COUNT; p++) {
            int senderIndex = random.nextInt(CLIENT_COUNT);
            Client sender = clients[senderIndex];

            int receiverCount = 1;
            //int receiverCount = 1 + random.nextInt(3); // at least one receiver
            int[] receivers = randomDistinctIndices(CLIENT_COUNT, receiverCount, senderIndex);

            int hopCount = 3 + random.nextInt(3); // at least three mix nodes
            int[] mixIndices = randomDistinctIndices(MIX_NODE_COUNT, hopCount, -1);
            byte[][] nodeList = new byte[hopCount][];
            ECPoint[] keyList = new ECPoint[hopCount];
            for (int i = 0; i < hopCount; i++) {
                nodeList[i] = mixNodeIds[mixIndices[i]];
                keyList[i] = mixNodePubs[mixIndices[i]];
            }

            if (receiverCount == 1) {
                byte[] destination = clientIds[receivers[0]];
                InstructionPacket packet = sender.createSphinxInstructionPacket(nodeList, keyList, destination, "test".getBytes());
                assertNotNull(packet);
            } else {
                int replicationIndex = mixIndices[0];
                byte[] replicationNode = mixNodeIds[replicationIndex];
                ECPoint replicationPub = mixNodePubs[replicationIndex];

                List<byte[][]> suffixPaths = new ArrayList<>();
                List<ECPoint[]> keySets = new ArrayList<>();
                for (int r = 0; r < receivers.length; r++) {
                    suffixPaths.add(new byte[][]{clientIds[receivers[r]]});
                    keySets.add(new ECPoint[]{clientPubs[receivers[r]]});
                }

                byte[] seed = new byte[16];
                random.nextBytes(seed);
                Pair<InstructionPacket, List<SubHeader>> pair = PolySphinxUtil.createPolySphinxPacketForTests(
                        params, replicationNode, replicationPub, suffixPaths, "test".getBytes(), seed, keySets);
                assertNotNull(pair.component1());
            }
        }
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
}