import MasterThesisFormat.Params;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.MixFormats.PolySphinx.PolySphinxUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.header.InstructionHeader;
import MasterThesisFormat.SerializationUtils;
import MasterThesisFormat.VM.VM;
import MasterThesisFormat.VM.VMContext;
import MasterThesisFormat.VM.VMOutput;
import MasterThesisFormat.instruction.InstructionRegister;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;

public class PolySphinxMacTest {

    private Params params;
    private BigInteger replicationPriv;
    private ECPoint replicationPub;
    private byte[] replicationNode;
    private List<byte[][]> suffixPaths;
    private List<ECPoint[]> keys;
    private BigInteger[] pathPrivs;
    private byte[] seed;
    private byte[] message;

    @Before
    public void setUp() throws Exception {
        params = new Params();
        replicationPriv = params.generatePrivateKey();
        replicationPub = params.derivePublicKey(replicationPriv);
        replicationNode = ClientUtil.encodeNode(1, 0);

        pathPrivs = new BigInteger[]{
                params.generatePrivateKey(),
                params.generatePrivateKey(),
                params.generatePrivateKey()
        };

        ECPoint[] pathPubs = new ECPoint[pathPrivs.length];
        for (int i = 0; i < pathPrivs.length; i++) {
            pathPubs[i] = params.derivePublicKey(pathPrivs[i]);
        }

        byte[][] pathNodes = new byte[pathPrivs.length][];
        for (int i = 0; i < pathNodes.length; i++) {
            pathNodes[i] = ClientUtil.encodeNode(i + 2, 0);
        }

        suffixPaths = new ArrayList<>();
        suffixPaths.add(pathNodes);

        keys = new ArrayList<>();
        keys.add(pathPubs);

        seed = new byte[16];
        new SecureRandom().nextBytes(seed);

        message = "hello".getBytes();
    }

    @Test
    public void testHeaderMac() throws Exception {
        InstructionPacket packet = PolySphinxUtil.createPolySphinxPacket(params, replicationNode, replicationPub, suffixPaths, message, seed, keys);

        // verify MAC at replication node and process packet
        packet = processAndCheck(packet, replicationPriv);

        InstructionHeader header = packet.getHeader();

        ECPoint alpha = header.getAlpha();
        ECPoint shared = params.getGroup().expon(alpha, replicationPriv);
        byte[] sharedReplicationKey = params.getAesKey(shared);


        // verify MACs for each relay node on the path
        for (BigInteger priv : pathPrivs) {
            packet = processAndCheck(packet, priv);
        }
    }

    private InstructionPacket processAndCheck(InstructionPacket packet, BigInteger privKey) throws Exception {
        InstructionHeader header = packet.getHeader();

        ECPoint alpha = header.getAlpha();
        ECPoint shared = params.getGroup().expon(alpha, privKey);
        byte[] sharedKey = params.getAesKey(shared);

        byte[] encInstr = header.getInstructions();
        byte[] plainInstr;
        if (encInstr.length == params.getInstructionTotalSize() - params.keyLength()) {
            plainInstr = params.xorRho(params.hrho(sharedKey), encInstr);
        } else {
            plainInstr = params.decrypt(sharedKey, encInstr);
        }

        byte[] expectedMac = params.mac(params.hmu(sharedKey), plainInstr);
        assertArrayEquals(expectedMac, header.getMAC());

        BigInteger b = params.hb(alpha, sharedKey);
        ECPoint nextAlpha = params.getGroup().expon(alpha, b);

        java.util.HashMap<Byte, byte[]> reg = new java.util.HashMap<>();
        reg.put(InstructionRegister.NEXT_ALPHA.getCode(), nextAlpha.getEncoded(true));
        reg.put(InstructionRegister.INSTRUCTIONS.getCode(), plainInstr);
        reg.put(InstructionRegister.MAC.getCode(), header.getMAC());
        reg.put(InstructionRegister.PAYLOAD.getCode(), packet.getPayload());

        VMContext ctx = new VMContext(reg);
        VM vm = new VM(privKey, params);
        java.util.List<VMOutput> outputs = vm.interpret(ctx);
        if (outputs.isEmpty()) {
            return null;
        }

        VMOutput out = outputs.get(0);
        InstructionHeader nextHeader = new InstructionHeader(
                SerializationUtils.decodeECPoint(out.getNextAlpha()),
                out.getInstructions(),
                out.getMAC()
        );
        return new InstructionPacket(nextHeader, out.getOutgoingPayload());
    }
}