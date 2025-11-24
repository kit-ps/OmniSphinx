import OmniSphinx.MixFormats.PolySphinx.SubHeader;
import OmniSphinx.Params;
import OmniSphinx.ClientUtil;
import OmniSphinx.MixFormats.PolySphinx.PolySphinxUtil;
import OmniSphinx.InstructionPacket.InstructionPacket;
import OmniSphinx.header.InstructionEncryptor;
import OmniSphinx.header.InstructionHeader;
import OmniSphinx.SerializationUtils;
import kotlin.Pair;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static OmniSphinx.SerializationUtils.concatenate;
import static org.junit.Assert.assertArrayEquals;

public class PolySphinxMacTest {

    private Params params;
    private BigInteger replicationPriv;
    private ECPoint replicationPub;
    private byte[] replicationNode;
    private List<byte[][]> suffixPaths;
    private List<ECPoint[]> keys;
    private List<byte[]> receivers;
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

        receivers = new ArrayList<>();
        receivers.add(Arrays.copyOf(ClientUtil.encodeNode(1001, 0), params.keyLength()));

        seed = new byte[16];
        new SecureRandom().nextBytes(seed);

        message = "hello".getBytes();
    }

    @Test
    public void testHeaderMac() throws Exception {
        Pair<InstructionPacket, List<SubHeader>> pair = PolySphinxUtil.createPolySphinxPacketForTests(params, replicationNode, replicationPub, suffixPaths, receivers, message, seed, keys);

        InstructionPacket packet = pair.component1();
        List<SubHeader> subHeaders = pair.component2();


        InstructionHeader header = packet.getHeader();

        ECPoint alpha = header.getAlpha();
        ECPoint shared = params.getGroup().expon(alpha, replicationPriv);
        byte[] replicationSecret = params.getAesKey(shared);


        // verify MACs for each relay node on the path
        for (int i = 0; i < subHeaders.size(); i++) {
            SubHeader subheader = subHeaders.get(i);

            int instructionLength = subheader.instructions.length;
            int toPad = params.getInstructionTotalSize() - instructionLength;

            byte[] padding = InstructionEncryptor.padInstructions(params, toPad, instructionLength, replicationSecret, i);

            subheader.instructions = concatenate(subheader.instructions, padding);

            header = new InstructionHeader(SerializationUtils.decodeECPoint(subheader.getAlpha()), subheader.getInstructions(), subheader.getMAC());
            for(int j = 0; j < pathPrivs.length; j++) {
                header = processAndCheck(header, pathPrivs[j]);
            }
        }
    }

    private InstructionHeader processAndCheck(InstructionHeader header, BigInteger privKey) throws Exception {


        ECPoint alpha = header.getAlpha();
        ECPoint shared = params.getGroup().expon(alpha, privKey);
        byte[] sharedKey = params.getAesKey(shared);

        byte[] encInstr = header.getInstructions();
        byte[] plainInstr = params.xorRho(params.hrho(sharedKey), encInstr);

        byte[] expectedMac = params.mac(params.hmu(sharedKey), encInstr);
        assertArrayEquals(expectedMac, header.getMAC());

        BigInteger b = params.hb(alpha, sharedKey);
        ECPoint nextAlpha = params.getGroup().expon(alpha, b);

        byte[] nextMAC = {};

        return new InstructionHeader(nextAlpha, plainInstr, nextMAC);
    }
}