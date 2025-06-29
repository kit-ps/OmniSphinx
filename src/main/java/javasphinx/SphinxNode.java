package javasphinx;

import javasphinx.crypto.ECCGroup;
import javasphinx.packet.ProcessedSphinxPacket;
import javasphinx.packet.SphinxPacket;
import javasphinx.packet.header.SphinxHeader;
import javasphinx.packet.header.SphinxPacketContent;
import MasterThesisFormat.routing.RoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Class representing a mix node
 */
public class SphinxNode {

    private final SphinxParams params;
    private final BigInteger secret;

    public SphinxNode(final SphinxParams params, final BigInteger secret) {
        this.params = params;
        this.secret = secret;
    }

    /**
     * Method that processes Sphinx packets at a mix node
     * @param sphinxPacketContent Header and encrypted payload of the Sphinx packet
     * @return The new header and payload of the Sphinx packet along with some auxiliary information
     */
    public ProcessedSphinxPacket sphinxProcess(SphinxPacketContent sphinxPacketContent) throws SphinxException {
        // Sammle notwendige Daten
        ECCGroup group = params.getGroup();
        ECPoint alpha = sphinxPacketContent.headerAndSecrets().sphinxHeader().getAlpha();
        byte[] beta = sphinxPacketContent.headerAndSecrets().sphinxHeader().getBeta();
        byte[] gamma = sphinxPacketContent.headerAndSecrets().sphinxHeader().getGamma();
        byte[] delta = sphinxPacketContent.delta();

        //Berechne das Shared Secret
        ECPoint s = group.expon(alpha, secret);
        byte[] aesS = params.getAesKey(s);

        if (beta.length != (params.headerLength() - 32)) {
            throw new SphinxException("Length of beta (" + beta.length + ") did not match expected length (" + (params.headerLength() - 32) + ")");
        }

        //Check MAC
        if (!Arrays.equals(gamma, params.mu(params.hmu(aesS), beta))) {
            throw new SphinxException("MAC mismatch");
        }

        //Pad Beta
        byte[] betaPadZeroes = new byte[2 * params.bodyLength()];
        Arrays.fill(betaPadZeroes, (byte) 0x00);
        byte[] betaPad = SerializationUtils.concatenate(beta, betaPadZeroes);

        //Decrypt Beta
        byte[] B = params.xorRho(params.hrho(aesS), betaPad);

        //Get length of routing
        byte length = B[0];

        byte[] routing = SerializationUtils.slice(B, 1, 1 + length);
        byte[] rest = SerializationUtils.slice(B, 1 + length, B.length);

        //used to identify previously seen elements of G
        byte[] tag = params.htau(aesS);

        //used to compute blinding factors
        BigInteger b = params.hb(alpha, aesS);

        //Blinding
        alpha = group.expon(alpha, b);


        gamma = SerializationUtils.slice(rest, params.keyLength());
        beta = SerializationUtils.slice(rest, params.keyLength(), params.keyLength() + (params.headerLength() - 32));

        //Entschlüsseln des Payloads
        delta = params.pii(params.hpi(aesS), delta);

        //???
        byte[] macKey = params.hpi(aesS);


        SphinxHeader sphinxHeader = new SphinxHeader(alpha, beta, gamma);

        //SphinxPacketContent sphinxPacketContent1 = new SphinxPacketContent(sphinxHeader, delta);

        //return new ProcessedSphinxPacket(tag, routing, sphinxPacketContent1, macKey);
        return null;
    }


}
