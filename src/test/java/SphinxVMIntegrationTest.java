import com.robertsoultanaev.javasphinx.SerializationUtils;
import com.robertsoultanaev.javasphinx.SphinxClient;
import com.robertsoultanaev.javasphinx.SphinxException;
import com.robertsoultanaev.javasphinx.SphinxParams;
import com.robertsoultanaev.javasphinx.VM.SphinxVM;
import com.robertsoultanaev.javasphinx.VM.VMException;
import com.robertsoultanaev.javasphinx.packet.ProcessedPacket;
import com.robertsoultanaev.javasphinx.packet.SphinxPacket;
import com.robertsoultanaev.javasphinx.packet.header.Header;
import com.robertsoultanaev.javasphinx.packet.header.PacketContent;
import com.robertsoultanaev.javasphinx.packet.instruction.SphinxInstructionPresets;
import com.robertsoultanaev.javasphinx.packet.message.DestinationAndMessage;
import com.robertsoultanaev.javasphinx.pki.PkiEntry;
import com.robertsoultanaev.javasphinx.routing.RandomRoutingStrategy;
import org.junit.Before;
import org.junit.Test;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.*;

import static org.junit.Assert.*;

public class SphinxVMIntegrationTest {

    private SphinxParams params;
    private SphinxClient client;
    private HashMap<Integer, PkiEntry> pkiPriv;
    private byte[][] nodesRouting;
    private ECPoint[] nodeKeys;
    private int[] useNodes;

    @Before
    public void setUp() throws SphinxException {
        params = new SphinxParams();
        client = new SphinxClient(params, new RandomRoutingStrategy());

        int r = 5;

        pkiPriv = new HashMap<>();
        HashMap<Integer, PkiEntry> pkiPub = new HashMap<>();

        for (int i = 0; i < 10; i++) {
            BigInteger x = params.getGroup().genSecret();
            ECPoint y = params.getGroup().expon(params.getGroup().getGenerator(), x);

            PkiEntry privEntry = new PkiEntry(x, y);
            PkiEntry pubEntry = new PkiEntry(null, y);

            pkiPriv.put(i, privEntry);
            pkiPub.put(i, pubEntry);
        }

        Integer[] pubKeys = pkiPub.keySet().toArray(new Integer[0]);
        // nodePool = node Ids
        int[] nodePool = new int[pubKeys.length];
        for (int i = 0; i < nodePool.length; i++) {
            nodePool[i] = pubKeys[i];
        }
        useNodes = client.route(nodePool, r);

        nodesRouting = new byte[useNodes.length][];
        for (int i = 0; i < useNodes.length; i++) {
            nodesRouting[i] = client.encodeNode(useNodes[i], (new Random()).nextInt());
        }

        nodeKeys = new ECPoint[useNodes.length];
        for (int i = 0; i < useNodes.length; i++) {
            nodeKeys[i] = pkiPub.get(useNodes[i]).pub();
        }
    }

    @Test
    public void testSphinxVMInstructionExecution() throws Exception {
        byte[] dest = "bob".getBytes();
        byte[] message = "Hello world from instructions!".getBytes();

        // Create packet (using classic Sphinx logic)
        PacketContent content = client.createForwardMessage(nodesRouting, nodeKeys, dest, message);
        SphinxPacket packet = new SphinxPacket(params, content);
        byte[] rawPacket = client.packMessageForInstructions(packet);

        // Get parameters for Instruction creation
        Header header = packet.packetContent().header();

        byte alphaLen = getAlphaLen(packet);
        byte betaLen = (byte) header.getBeta().length;
        byte kappa = (byte) header.getGamma().length;
        System.out.println(alphaLen);
        // Instruction parameter setup (assumed fixed here)
        byte HASH_TYPE_MAC = 0x10;
        byte HASH_TYPE_PRG = 0x02;
        byte MAC_TYPE = 0x01;
        byte DECRYPT_ALGO = 0x04;
        byte BLINDING_HASH = 0x15;
        byte GROUP_ID = 0x00;
        byte HASH_TYPE_KEY = 0x14;

        // Generate VM instructions
        byte[] instructions = SphinxInstructionPresets.createInstructions(
                alphaLen, betaLen, kappa, HASH_TYPE_KEY, HASH_TYPE_MAC, HASH_TYPE_PRG, MAC_TYPE, DECRYPT_ALGO, BLINDING_HASH, GROUP_ID
        );

        // Run VM
        BigInteger secret = pkiPriv.get(useNodes[0]).priv(); // Private key of first node
        SphinxVM vm = new SphinxVM(secret);
        ProcessedPacket result = vm.interpret(rawPacket, instructions);

        assertNotNull("Processed packet should not be null", result);
        assertNotNull("Routing field must be extracted", result.routing());
        assertNotNull("Payload must be processed", result.packetContent());
    }

    private byte getAlphaLen(SphinxPacket packet) throws VMException {
        int alphaLen = SerializationUtils.encodeECPoint(packet.packetContent().header().alpha()).length;
        if(alphaLen > 255) {
            throw new VMException("Alpha hat einen höheren Wert als 255?!");
        }
        return (byte) alphaLen;
    }
}
