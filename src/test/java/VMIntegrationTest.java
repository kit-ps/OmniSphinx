import MasterThesisFormat.MixFormats.Packet;
import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import javasphinx.SphinxClient;
import javasphinx.SphinxException;
import MasterThesisFormat.VM.VM;
import MasterThesisFormat.VM.VMException;
import javasphinx.packet.SphinxPacket;
import javasphinx.packet.header.SphinxHeader;
import MasterThesisFormat.instruction.Instruction;
import MasterThesisFormat.MixFormats.Sphinx.SphinxInstructionPresets;
import MasterThesisFormat.pki.PkiEntry;
import org.junit.Before;
import org.junit.Test;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.*;

import static org.junit.Assert.*;

public class VMIntegrationTest {

    private Params params;
    private SphinxClient client;
    private HashMap<Integer, PkiEntry> pkiPriv;
    private byte[][] nodesRouting;
    private ECPoint[] nodeKeys;
    private int[] useNodes;

    @Before
    public void setUp() throws SphinxException {
        params = new Params();
        //client = new SphinxClient(params);

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
        //useNodes = client.route(nodePool, r);

        nodesRouting = new byte[useNodes.length][];
        for (int i = 0; i < useNodes.length; i++) {
            //nodesRouting[i] = client.encodeNode(useNodes[i], (new Random()).nextInt());
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
        //SphinxPacket packet = client.createForwardMessage(nodesRouting, nodeKeys, dest, message);
        SphinxPacket packet = null;
        byte[] rawPacket = client.packMessageForInstructions(packet);

        // Get parameters for Instruction creation
        SphinxHeader sphinxHeader = packet.getHeader();

        byte alphaLen = getAlphaLen(packet);
        byte betaLen = (byte) sphinxHeader.getBeta().length;
        byte kappa = (byte) sphinxHeader.getGamma().length;

        // Generate VM instructions
        byte[] instructions = SphinxInstructionPresets.createInstructions(nodesRouting[0][0]);
        // Run VM
        BigInteger secret = pkiPriv.get(useNodes[0]).priv(); // Private key of first node
        //SphinxNode node = new SphinxNode(params, new RandomRoutingStrategy(), secret);
        //node.sphinxProcess(packet.packetContent());
        VM vm = new VM(secret, params);
        Packet result = vm.interpret(rawPacket, instructions);

        assertNotNull("Processed packet should not be null", result);
        //assertNotNull("Routing field must be extracted", result.routing());
        //assertNotNull("Payload must be processed", result.sphinxPacket());
    }

    @Test
    public void testForLoop() throws Exception {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        byte instrCount = 4;
        instr.write(Instruction.forLoop( (byte) 2, instrCount));


        instr.write(Instruction.concate((byte) 0x00, (byte) 0x00, (byte) 0x00));
        instr.write(Instruction.concate((byte) 0x00, (byte) 0x00, (byte) 0x00));
        instr.write(Instruction.concate((byte) 0x00, (byte) 0x00, (byte) 0x00));
        instr.write(Instruction.concate((byte) 0x00, (byte) 0x00, (byte) 0x00));

        instr.write(Instruction.concate((byte) 0x00, (byte) 0x00, (byte) 0x00));
        byte[] inst = instr.toByteArray();

        VM vm = new VM(null, params);

        vm.interpret(null, inst);
    }

    private byte getAlphaLen(SphinxPacket packet) throws VMException {
        int alphaLen = SerializationUtils.encodeECPoint(packet.getHeader().getAlpha()).length;
        if(alphaLen > 255) {
            throw new VMException("Alpha hat einen höheren Wert als 255?!");
        }
        return (byte) alphaLen;
    }
}
