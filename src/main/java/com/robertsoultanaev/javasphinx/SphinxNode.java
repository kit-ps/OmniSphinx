package com.robertsoultanaev.javasphinx;

import com.robertsoultanaev.javasphinx.crypto.ECCGroup;
import com.robertsoultanaev.javasphinx.packet.ProcessedPacket;
import com.robertsoultanaev.javasphinx.packet.SphinxPacket;
import com.robertsoultanaev.javasphinx.packet.header.Header;
import com.robertsoultanaev.javasphinx.packet.header.PacketContent;
import com.robertsoultanaev.javasphinx.packet.instruction.SphinxInstructionPresets;
import com.robertsoultanaev.javasphinx.routing.RoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Class representing a mix node
 */
public class SphinxNode {

    private final SphinxParams params;
    private final SphinxClient client;
    private final BigInteger secret;

    public SphinxNode(final SphinxParams params, final RoutingStrategy routingStrategy, final BigInteger secret) {
        this.params = params;
        this.client = new SphinxClient(params, routingStrategy);
        this.secret = secret;
    }

    public SphinxClient client() {
        return client;
    }

    /**
     * Method that processes Sphinx packets at a mix node
     * @param packetContent Header and encrypted payload of the Sphinx packet
     * @return The new header and payload of the Sphinx packet along with some auxiliary information
     */
    public ProcessedPacket sphinxProcess(PacketContent packetContent) throws SphinxException, IOException {
        // Sammle notwendige Daten
        ECCGroup group = params.getGroup();
        ECPoint alpha = packetContent.header().alpha();
        byte[] beta = packetContent.header().beta();
        byte[] gamma = packetContent.header().gamma();
        byte[] delta = packetContent.delta();

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


        Header header = new Header(alpha, beta, gamma);

        PacketContent packetContent1 = new PacketContent(header, delta);

        return new ProcessedPacket(tag, routing, packetContent1, macKey);
    }

    public SphinxPacket repack(ProcessedPacket packet) {
        return new SphinxPacket(params, packet.packetContent());
    }

}
