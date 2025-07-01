package javasphinx;

import MasterThesisFormat.Params;
import javasphinx.crypto.ECCGroup;
import javasphinx.packet.RoutingFlag;
import javasphinx.packet.SphinxPacket;
import javasphinx.packet.header.SphinxHeader;
import javasphinx.packet.header.HeaderAndSecrets;
import java.nio.ByteBuffer;
import javasphinx.packet.message.DestinationAndMessage;
import javasphinx.packet.reply.NymTuple;
import javasphinx.packet.reply.SingleUseReplyBlock;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import static javasphinx.SerializationUtils.concatenate;
import static javasphinx.SerializationUtils.slice;

/**
 * Class housing the methods to create, package and receive Sphinx messages.
 */
public class SphinxClient {

    public static final int MAX_DEST_SIZE = 127;

    /**
     * Create a Sphinx header with the shared secrets.
     * @param nodelist List of encoded mix node identifiers used to route the Sphinx packet.
     * @param dest Final destination of the Sphinx packet.
     * @return Header and the list of secrets used to encrypt the payload in a nested manner.
     */
    private static HeaderAndSecrets createHeader(byte[][] nodelist, ECPoint[] alphas,
                                                 ECPoint[] sharedSecrets, byte[] dest,
                                                 Params params) throws SphinxException, IOException {

        byte[][] nodeMeta = new byte[nodelist.length][];
        for (int i = 0; i < nodelist.length; i++) {
            byte[] node = nodelist[i];
            byte[] nodeLength = {(byte) node.length};
            nodeMeta[i] = concatenate(nodeLength, node);
        }

        int nu = nodelist.length;

        if (alphas.length != nu || sharedSecrets.length != nu) {
            throw new SphinxException("Parameter length mismatch");
        }

        byte[][] aesKeys = new byte[nu][];
        for (int i = 0; i < nu; i++) {
            aesKeys[i] = params.getAesKey(sharedSecrets[i]);
        }

        byte[] phi = {};
        int minLen = params.headerLength() - 32;

        for (int i = 1; i < nu; i++) {
            byte[] zeroes1 = new byte[params.keyLength() + nodeMeta[i].length];
            Arrays.fill(zeroes1, (byte) 0x00);
            byte[] plain = concatenate(phi, zeroes1);

            byte[] zeroes2 = new byte[minLen];
            Arrays.fill(zeroes2, (byte) 0x00);
            byte[] zeroes2plain = concatenate(zeroes2, plain);
            phi = params.xorRho(params.hrho(aesKeys[i - 1]), zeroes2plain);
            phi = slice(phi, minLen, phi.length);

            minLen -= nodeMeta[i].length + params.keyLength();
        }

        int lenMeta = 0;
        for (int i = 1; i < nodeMeta.length; i++) {
            lenMeta += nodeMeta[i].length;
        }

        if (phi.length != lenMeta + (nu-1)*params.keyLength()) {
            throw new SphinxException("Length of phi (" + phi.length + ") did not match the expected length (" + (lenMeta + (nu-1)*params.keyLength()) + ")");
        }

        byte[] destLength = {(byte) dest.length};
        byte[] finalRouting = concatenate(destLength, dest);

        int randomPadLen = (params.headerLength() - 32) - lenMeta - (nu-1)*params.keyLength() - finalRouting.length;
        if (randomPadLen < 0) {
            throw new SphinxException("Length of random pad (" + randomPadLen + ") must be non-negative");
        }

        SecureRandom secureRandom = new SecureRandom();
        byte[] randomPad = new byte[randomPadLen];
        secureRandom.nextBytes(randomPad);

        byte[] beta = concatenate(finalRouting, randomPad);
        beta = params.xorRho(params.hrho(aesKeys[nu - 1]), beta);
        beta = concatenate(beta, phi);

        byte[] gamma = params.mu(params.hmu(aesKeys[nu - 1]), beta);

        for (int i = nu - 2; i >= 0; i--) {
            byte[] nodeId = nodeMeta[i+1];

            int plainBetaLen = (params.headerLength() - 32) - params.keyLength() - nodeId.length;
            byte[] plainBeta = slice(beta, plainBetaLen);
            byte[] plain = concatenate(nodeId, gamma, plainBeta);

            beta = params.xorRho(params.hrho(aesKeys[i]), plain);
            gamma = params.mu(params.hmu(aesKeys[i]), beta);
        }
        SphinxHeader sphinxHeader = new SphinxHeader(alphas[0], beta, gamma);

        return new HeaderAndSecrets(sphinxHeader, aesKeys, alphas);
    }

    /**
     * Create a Sphinx header that additionally encodes a delay inside the beta
     * field. The delay is stored as a 4 byte integer at the start of beta.
     */
    private static HeaderAndSecrets createHeaderWithDelay(byte[][] nodelist, ECPoint[] alphas,
                                                          ECPoint[] sharedSecrets, byte[] dest,
                                                          int delay, Params params) throws SphinxException, IOException {

        byte[][] nodeMeta = new byte[nodelist.length][];
        for (int i = 0; i < nodelist.length; i++) {
            byte[] node = nodelist[i];
            byte[] nodeLength = {(byte) node.length};
            nodeMeta[i] = concatenate(nodeLength, node);
        }

        int nu = nodelist.length;

        if (alphas.length != nu || sharedSecrets.length != nu) {
            throw new SphinxException("Parameter length mismatch");
        }

        byte[][] aesKeys = new byte[nu][];
        for (int i = 0; i < nu; i++) {
            aesKeys[i] = params.getAesKey(sharedSecrets[i]);
        }

        byte[] phi = {};
        int minLen = params.headerLength() - 32;

        for (int i = 1; i < nu; i++) {
            byte[] zeroes1 = new byte[params.keyLength() + nodeMeta[i].length];
            Arrays.fill(zeroes1, (byte) 0x00);
            byte[] plain = concatenate(phi, zeroes1);

            byte[] zeroes2 = new byte[minLen];
            Arrays.fill(zeroes2, (byte) 0x00);
            byte[] zeroes2plain = concatenate(zeroes2, plain);
            phi = params.xorRho(params.hrho(aesKeys[i - 1]), zeroes2plain);
            phi = slice(phi, minLen, phi.length);

            minLen -= nodeMeta[i].length + params.keyLength();
        }

        int lenMeta = 0;
        for (int i = 1; i < nodeMeta.length; i++) {
            lenMeta += nodeMeta[i].length;
        }

        if (phi.length != lenMeta + (nu-1)*params.keyLength()) {
            throw new SphinxException("Length of phi (" + phi.length + ") did not match the expected length (" + (lenMeta + (nu-1)*params.keyLength()) + ")");
        }

        byte[] destLength = {(byte) dest.length};
        byte[] delayBytes = ByteBuffer.allocate(4).putInt(delay).array();
        byte[] finalRouting = concatenate(delayBytes, destLength, dest);

        int randomPadLen = (params.headerLength() - 32) - lenMeta - (nu-1)*params.keyLength() - finalRouting.length;
        if (randomPadLen < 0) {
            throw new SphinxException("Length of random pad (" + randomPadLen + ") must be non-negative");
        }

        SecureRandom secureRandom = new SecureRandom();
        byte[] randomPad = new byte[randomPadLen];
        secureRandom.nextBytes(randomPad);

        byte[] beta = concatenate(finalRouting, randomPad);
        beta = params.xorRho(params.hrho(aesKeys[nu - 1]), beta);
        beta = concatenate(beta, phi);

        byte[] gamma = params.mu(params.hmu(aesKeys[nu - 1]), beta);

        for (int i = nu - 2; i >= 0; i--) {
            byte[] nodeId = nodeMeta[i+1];

            int plainBetaLen = (params.headerLength() - 32) - params.keyLength() - nodeId.length;
            byte[] plainBeta = slice(beta, plainBetaLen);
            byte[] plain = concatenate(nodeId, gamma, plainBeta);

            beta = params.xorRho(params.hrho(aesKeys[i]), plain);
            gamma = params.mu(params.hmu(aesKeys[i]), beta);
        }
        SphinxHeader sphinxHeader = new SphinxHeader(alphas[0], beta, gamma);

        return new HeaderAndSecrets(sphinxHeader, aesKeys, alphas);
    }


    /**
     * Create a forward Sphinx message.
     * @param nodelist List of encoded mix node identifiers used to route the Sphinx packet.
     * @param destination Final destination.
     * @param message Data payload.
     * @return Header and payload of a Sphinx packet encrypted in a nested manner.
     */
    public static SphinxPacket createForwardPacket(byte[][] nodelist, ECPoint[] alphas,
                                                   ECPoint[] sharedSecrets, byte[] destination,
                                                   byte[] message, Params params) throws SphinxException, IOException {        if (!(destination.length > 0 && destination.length < MAX_DEST_SIZE)) {
            throw new SphinxException("Destination has to be between 1 and " + MAX_DEST_SIZE + " bytes long");
        }

        MessageBufferPacker packer;

        packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(1);
            packer.packString(RoutingFlag.DESTINATION.value());
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack the destination flag");
        }

        byte[] finalDestination = packer.toByteArray();
        HeaderAndSecrets headerAndSecrets = createHeader(nodelist, alphas, sharedSecrets, finalDestination, params);

        packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(2);
            packer.packBinaryHeader(destination.length);
            packer.writePayload(destination);
            packer.packBinaryHeader(message.length);
            packer.writePayload(message);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack destination and message");
        }

        byte[] encodedDestAndMsg = packer.toByteArray();

        byte[][] secrets = headerAndSecrets.secrets();
        byte[] payload = padBody(params.bodyLength() - params.keyLength(), encodedDestAndMsg);
        byte[] mac = params.mu(params.hpi(secrets[nodelist.length - 1]), payload);
        byte[] body = concatenate(mac, payload);

        byte[] delta = params.pi(params.hpi(secrets[nodelist.length - 1]), body);

        for (int i = nodelist.length - 2; i >= 0; i--) {
            delta = params.pi(params.hpi(secrets[i]), delta);
        }

        return new SphinxPacket(params, headerAndSecrets.sphinxHeader(), delta);
    }

    /**
     * Create a forward Sphinx message that carries a delay value encoded in the
     * beta field. The mix node processing this packet SHOULD delay forwarding by
     * the specified number of milliseconds.
     */
    public static SphinxPacket createForwardPacketWithDelay(byte[][] nodelist, ECPoint[] alphas,
                                                            ECPoint[] sharedSecrets, byte[] destination,
                                                            byte[] message, int delay, Params params) throws SphinxException, IOException {
        if (!(destination.length > 0 && destination.length < MAX_DEST_SIZE)) {
            throw new SphinxException("Destination has to be between 1 and " + MAX_DEST_SIZE + " bytes long");
        }

        MessageBufferPacker packer;

        packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(1);
            packer.packString(RoutingFlag.DESTINATION.value());
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack the destination flag");
        }

        byte[] finalDestination = packer.toByteArray();
        HeaderAndSecrets headerAndSecrets = createHeaderWithDelay(nodelist, alphas, sharedSecrets, finalDestination, delay, params);

        packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(2);
            packer.packBinaryHeader(destination.length);
            packer.writePayload(destination);
            packer.packBinaryHeader(message.length);
            packer.writePayload(message);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack destination and message");
        }

        byte[] encodedDestAndMsg = packer.toByteArray();

        byte[][] secrets = headerAndSecrets.secrets();
        byte[] payload = padBody(params.bodyLength() - params.keyLength(), encodedDestAndMsg);
        byte[] mac = params.mu(params.hpi(secrets[nodelist.length - 1]), payload);
        byte[] body = concatenate(mac, payload);

        byte[] delta = params.pi(params.hpi(secrets[nodelist.length - 1]), body);

        for (int i = nodelist.length - 2; i >= 0; i--) {
            delta = params.pi(params.hpi(secrets[i]), delta);
        }

        return new SphinxPacket(params, headerAndSecrets.sphinxHeader(), delta);
    }


    /**
     * Create a single-use reply block to receive replies anonymously.
     * @param nodelist List of encoded mix node identifiers used to route the Sphinx packet.
     * @param dest Final destination of the Sphinx packet.
     * @return An identifier for the SURB, key tuple to receive a message addressed to this SURB, and the reply block itself.
     */
    public static SingleUseReplyBlock createSurb(byte[][] nodelist, ECPoint[] alphas,
                                                 ECPoint[] sharedSecrets, byte[] dest,
                                                 Params params) throws SphinxException, IOException {
        SecureRandom secureRandom = new SecureRandom();
        int nu = nodelist.length;

        byte[] xid = new byte[params.keyLength()];
        secureRandom.nextBytes(xid);

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(3);
            packer.packString(RoutingFlag.SURB.value());
            packer.packBinaryHeader(dest.length);
            packer.writePayload(dest);
            packer.packBinaryHeader(xid.length);
            packer.writePayload(xid);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack SURB");
        }

        byte[] finalDest = packer.toByteArray();
        HeaderAndSecrets headerAndSecrets = createHeader(nodelist, alphas, sharedSecrets, finalDest, params);

        byte[] ktilde = new byte[params.keyLength()];
        secureRandom.nextBytes(ktilde);

        byte[][] hashedSecrets = new byte[headerAndSecrets.secrets().length][];
        for (int i = 0; i < hashedSecrets.length; i++) {
            hashedSecrets[i] = params.hpi(headerAndSecrets.secrets()[i]);
        }

        byte[][] keytuple = new byte[hashedSecrets.length + 1][];
        keytuple[0] = ktilde;

        System.arraycopy(hashedSecrets, 0, keytuple, 1, keytuple.length - 1);

        NymTuple nymTuple = new NymTuple(nodelist[0], headerAndSecrets.sphinxHeader(), ktilde);

        return new SingleUseReplyBlock(xid, keytuple, nymTuple);
    }

    /**
     * Package a Sphinx reply message addressed to the nymTuple.
     * @param nymTuple The reply block received from the anonymous sender.
     * @param message The data payload of the Sphinx packet.
     * @return Header and payload of a Sphinx packet encrypted in a nested manner.
     */
//    public SphinxPacketContent packageSurb(NymTuple nymTuple, byte[] message, Params params) throws SphinxException {
//        byte[] zeroes = new byte[params.keyLength()];
//        Arrays.fill(zeroes, (byte) 0x00);
//        byte[] zeroPaddedMessage = concatenate(zeroes, message);
//        byte[] body = padBody(params.bodyLength(), zeroPaddedMessage);
//        byte[] delta = params.pi(nymTuple.kTilde(), body);
//
//        return new SphinxPacketContent(nymTuple.sphinxHeader(), delta);
//    }

    /**
     * Receive a forward Sphinx message.
     * @param macKey Key used to compute the MAC on the payload.
     * @param delta The payload of the Sphinx message.
     * @return Final destination and data payload of the Sphinx message.
     */
    public static DestinationAndMessage receiveForward(byte[] macKey, byte[] delta, Params params) throws SphinxException {
        byte[] mac = slice(delta, params.keyLength());
        byte[] body = slice(delta, params.keyLength(), delta.length);

        byte[] expectedMac = params.mu(macKey, body);

        if (!Arrays.equals(mac, expectedMac)) {
            String messageMacStr = Hex.toHexString(mac);
            String expectedMacStr = Hex.toHexString(expectedMac);
            throw new SphinxException("Provided MAC (" + messageMacStr + ") did not match the expected MAC (" + expectedMacStr + ")");
        }

        byte[] encodedDestAndMsg = unpadBody(slice(delta, params.keyLength(), delta.length));
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(encodedDestAndMsg);
        byte[] destination;
        byte[] message;
        try {
            unpacker.unpackArrayHeader();
            int destLength = unpacker.unpackBinaryHeader();
            destination = unpacker.readPayload(destLength);
            int msgLength = unpacker.unpackBinaryHeader();
            message = unpacker.readPayload(msgLength);
            unpacker.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to unpack the destination and message");
        }

        return new DestinationAndMessage(destination, message);
    }

    /**
     * Receive a reply to a Sphinx message addressed to a SURB.
     * @param keytuple Key tuple used to receive the message addressed to a SURB.
     * @param delta The encrypted data payload of the Sphinx packet.
     * @return The data payload of the Sphinx packet.
     */
    public static byte[] receiveSurb(byte[][] keytuple, byte[] delta, Params params) throws SphinxException {
        byte[] ktilde = keytuple[0];
        for (int i = keytuple.length - 1; i > 0; i--) {
            delta = params.pi(keytuple[i], delta);
        }
        delta = params.pii(ktilde, delta);

        byte[] zeroes = new byte[params.keyLength()];
        Arrays.fill(zeroes, (byte) 0x00);

        if (!Arrays.equals(slice(delta, params.keyLength()), zeroes)) {
            String deltaPrefix = Hex.toHexString(slice(delta, params.keyLength()));
            String expectedPrefix = Hex.toHexString(zeroes);
            throw new SphinxException("Prefix of delta (" + deltaPrefix + ") did not match the expected prefix (" + expectedPrefix + ")");
        }

        return unpadBody(slice(delta, params.keyLength(), delta.length));
    }

    /**
     * Package a Sphinx message into binary format for the Instructions to interpret.
     * @param sphinxPacket Sphinx packet and the Sphinx parameter lengths.
     * @return Sphinx message in binary format.
     */
    public static byte[] packMessageForInstructions(SphinxPacket sphinxPacket) throws SphinxException {

        SphinxHeader sphinxHeader = sphinxPacket.getHeader();
        byte[] encodedAlpha = SerializationUtils.encodeECPoint(sphinxHeader.getAlpha());
        byte[] beta = sphinxHeader.getBeta();
        byte[] gamma = sphinxHeader.getGamma();
        byte[] delta = sphinxPacket.getDelta();

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(encodedAlpha);
            out.write(beta);
            out.write(gamma);
            out.write(delta);
        } catch (IOException e) {
            throw new SphinxException("Failed to build message byte stream");
        }
        return out.toByteArray();
    }

    /**
     * Package a Sphinx message into binary format.
     * @param sphinxPacket Sphinx packet and the Sphinx parameter lengths.
     * @return Sphinx message in binary format.
     */
    public static byte[] packMessage(SphinxPacket sphinxPacket) throws SphinxException {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();

        int headerLength = sphinxPacket.headerLength();
        int bodyLength = sphinxPacket.bodyLength();

        SphinxHeader sphinxHeader = sphinxPacket.getHeader();
        byte[] delta = sphinxPacket.getDelta();
        byte[] packedEcPoint = packECPoint(sphinxHeader.getAlpha());

        try {
            packer.packArrayHeader(2);
            packer.packArrayHeader(2);
            packer.packInt(headerLength);
            packer.packInt(bodyLength);
            packer.packArrayHeader(2);
            packer.packArrayHeader(3);
            packer.packExtensionTypeHeader((byte) 2, packedEcPoint.length);
            packer.writePayload(packedEcPoint);
            packer.packBinaryHeader(sphinxHeader.getBeta().length);
            packer.writePayload(sphinxHeader.getBeta());
            packer.packBinaryHeader(sphinxHeader.getGamma().length);
            packer.writePayload(sphinxHeader.getGamma());
            packer.packBinaryHeader(delta.length);
            packer.writePayload(delta);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack the sphinx packet");
        }

        return packer.toByteArray();
    }

    /**
     * Unpack a binary message into a SphinxPacket type.
     * @param m Binary message.
     * @return Binary message serialised into SphinxPacket type.
     */
    public static SphinxPacket unpackMessage(byte[] m, Params params) throws SphinxException, IOException {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(m);
        int headerLength, bodyLength;
        byte[] packedAlpha, beta, gamma, delta;
        try {
            unpacker.unpackArrayHeader();
            unpacker.unpackArrayHeader();
            headerLength = unpacker.unpackInt();
            bodyLength = unpacker.unpackInt();
            unpacker.unpackArrayHeader();
            unpacker.unpackArrayHeader();
            int alphaLength = unpacker.unpackExtensionTypeHeader().getLength();
            packedAlpha = unpacker.readPayload(alphaLength);
            int betaLength = unpacker.unpackBinaryHeader();
            beta = unpacker.readPayload(betaLength);
            int gammaLength = unpacker.unpackBinaryHeader();
            gamma = unpacker.readPayload(gammaLength);
            int deltaLength = unpacker.unpackBinaryHeader();
            delta = unpacker.readPayload(deltaLength);
            unpacker.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to unpack the sphinx packet");
        }

        unpacker = MessagePack.newDefaultUnpacker(packedAlpha);
        byte[] encodedAlpha;
        try {
            unpacker.unpackArrayHeader();
            unpacker.unpackInt();
            int encodedAlphaLength = unpacker.unpackBinaryHeader();
            encodedAlpha = unpacker.readPayload(encodedAlphaLength);
            unpacker.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to unpack alpha");
        }

        ECPoint alpha = SerializationUtils.decodeECPoint(encodedAlpha);

        SphinxHeader sphinxHeader = new SphinxHeader(alpha, beta, gamma);

        //SphinxPacketContent sphinxPacketContent = new SphinxPacketContent(sphinxHeader, delta);

        return null;
        //return new SphinxPacket(params, sphinxPacketContent.sphinxHeader(), sphinxPacketContent.delta());
    }

    /**
     * Compute the maximum number of bytes that can be a packet into a single Sphinx packet payload with the given parameters.
     * @return Maximum number of bytes that can be a packet into a single Sphinx packet payload with the given parameters.
     */
    public static int getMaxPayloadSize(Params params) throws SphinxException {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(2);
            packer.packBinaryHeader(MAX_DEST_SIZE);
            packer.packBinaryHeader(params.bodyLength());
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to calculate the msgpack overhead");
        }

        int msgPackOverhead = packer.getBufferSize();

        // Added in padBody
        int padByteLength = 1;

        return params.bodyLength() - params.keyLength() - padByteLength - msgPackOverhead;
    }

    private static byte[] padBody(int msgtotalsize, byte[] body) throws SphinxException {
        byte[] initialPadByte = {(byte) 0x7f};
        int numPadBytes = msgtotalsize - (body.length + 1);

        if (numPadBytes < 0) {
            throw new SphinxException("Insufficient space for message");
        }

        byte[] padBytes = new byte[numPadBytes];
        Arrays.fill(padBytes, (byte) 0xff);

        return concatenate(body, initialPadByte, padBytes);
    }

    private static byte[] unpadBody(byte[] body) {
        int l = body.length - 1;
        byte xMarker = (byte) 0x7f;
        byte fMarker = (byte) 0xff;

        while (body[l] == fMarker && l > 0) {
            l--;
        }

        byte[] ret = {};

        if (body[l] == xMarker) {
            ret = slice(body, l);
        }

        return ret;
    }

    public static byte[] packECPoint(ECPoint ecPoint) throws SphinxException {
        byte[] encodedEcPoint = SerializationUtils.encodeECPoint(ecPoint);

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(2);
            packer.packInt(ECCGroup.DEFAULT_CURVE_NID);
            packer.packBinaryHeader(encodedEcPoint.length);
            packer.writePayload(encodedEcPoint);
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to pack the sphinx packet");
        }

        return packer.toByteArray();
    }
}
