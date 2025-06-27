package javasphinx;

import javasphinx.crypto.ECCGroup;
import javasphinx.packet.RoutingFlag;
import javasphinx.packet.SphinxPacket;
import javasphinx.packet.header.SphinxHeader;
import javasphinx.packet.header.HeaderAndSecrets;
import javasphinx.packet.header.PacketContent;
import javasphinx.packet.message.DestinationAndMessage;
import javasphinx.packet.reply.NymTuple;
import javasphinx.packet.reply.SingleUseReplyBlock;
import javasphinx.routing.RoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static javasphinx.SerializationUtils.concatenate;
import static javasphinx.SerializationUtils.slice;

/**
 * Class housing the methods to create, package and receive Sphinx messages.
 */
public class SphinxClient {

    public static final int MAX_DEST_SIZE = 127;

    private final SphinxParams params;
    private final RoutingStrategy routingStrategy;

    public SphinxClient(final SphinxParams params, final RoutingStrategy routingStrategy) {
        this.params = params;
        this.routingStrategy = routingStrategy;
    }

    public SphinxPacket createPacket(PacketContent packetContent) {
        return new SphinxPacket(params, packetContent.sphinxHeader(), packetContent.delta());
    }

    public SphinxParams params() {
        return params;
    }

    /**
     * Encode the mix node nextNodeId into binary format.
     * @param idnum Identifier of the mix node.
     * @param additionalInfo packet identifier, the first mix uses this to route reply packets
     * @return Identifier of the mix node in binary format.
     */
    public byte[] encodeNode(int idnum, int additionalInfo) throws SphinxException {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();

        try {
            // This is NOT specific to the string, this is the amount of 2 byte values following, regardless of type!!!
            packer.packArrayHeader(3);
            packer.packString(RoutingFlag.RELAY.value()); //2 bytes
            packer.packInt(idnum); //2 bytes
            packer.packInt(additionalInfo); //2 bytes
            packer.close();
        } catch (IOException ex) {
            throw new SphinxException("Failed to encode node");
        }

        return packer.toByteArray();
    }

    /**
     * Select a subset of mix node identifiers according to the Client's {@link RoutingStrategy}
     * @param identifiers list of mix node ids
     * @param mixCount count of ids to select from identifiers
     * @return mix identifiers
     */
    public int[] route(int[] identifiers, int mixCount) throws SphinxException {
        if (identifiers.length < mixCount) {
            throw new SphinxException("Number of possible elements (%d) was less than the requested number (%d)"
                    .formatted(identifiers.length, mixCount));
        }
        return routingStrategy.route(identifiers, mixCount);
    }

    /**
     * Create a Sphinx header.
     * @param nodelist List of encoded mix node identifiers used to route the Sphinx packet.
     * @param keys List of the corresponding public keys of the mix nodes in nodelist.
     * @param dest Final destination of the Sphinx packet.
     * @return Header and the list of secrets used to encrypt the payload in a nested manner.
     */
    public HeaderAndSecrets createHeader(byte[][] nodelist, ECPoint[] keys, byte[] dest) throws SphinxException, IOException {
        class HeaderRecord {
            final ECPoint alpha;
            final ECPoint s;
            final BigInteger b;
            final byte[] aes;

            HeaderRecord(ECPoint alpha, ECPoint s, BigInteger b, byte[] aes) {
                this.alpha = alpha;
                this.s = s;
                this.b = b;
                this.aes = aes;
            }
        }

        byte[][] nodeMeta = new byte[nodelist.length][];
        for (int i = 0; i < nodelist.length; i++) {
            byte[] node = nodelist[i];
            byte[] nodeLength = {(byte) node.length};
            nodeMeta[i] = concatenate(nodeLength, node);
        }

        int nu = nodelist.length;
        ECCGroup group = params.getGroup();

        BigInteger blindFactor = group.genSecret();
        List<HeaderRecord> asbtuples = new ArrayList<>();

        for (ECPoint k : keys) {
            ECPoint alpha = group.expon(group.getGenerator(), blindFactor);
            ECPoint s = group.expon(k, blindFactor);
            byte[] aesS = params.getAesKey(s);

            BigInteger b = params.hb(alpha, aesS);
            blindFactor = blindFactor.multiply(b);
            blindFactor = blindFactor.mod(group.getOrder());

            HeaderRecord headerRecord = new HeaderRecord(alpha, s, b, aesS);

            asbtuples.add(headerRecord);
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
            phi = params.xorRho(params.hrho(asbtuples.get(i-1).aes), zeroes2plain);
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
        beta = params.xorRho(params.hrho(asbtuples.get(nu - 1).aes), beta);
        beta = concatenate(beta, phi);

        byte[] gamma = params.mu(params.hmu(asbtuples.get(nu-1).aes), beta);

        for (int i = nu - 2; i >= 0; i--) {
            byte[] nodeId = nodeMeta[i+1];

            int plainBetaLen = (params.headerLength() - 32) - params.keyLength() - nodeId.length;
            byte[] plainBeta = slice(beta, plainBetaLen);
            byte[] plain = concatenate(nodeId, gamma, plainBeta);

            beta = params.xorRho(params.hrho(asbtuples.get(i).aes), plain);
            gamma = params.mu(params.hmu(asbtuples.get(i).aes), beta);
        }
        //byte[] instructions = SphinxInstructionPresets.createSphinxInstructionsForAnotherSphinxNode();
        SphinxHeader sphinxHeader = new SphinxHeader(asbtuples.get(0).alpha, beta, gamma);

        byte[][] secrets = new byte[asbtuples.size()][];
        for (int i = 0; i < asbtuples.size(); i++) {
            secrets[i] = asbtuples.get(i).aes;
        }

        return new HeaderAndSecrets(sphinxHeader, secrets);
    }

    /**
     * Create a forward Sphinx message.
     * @param nodelist List of encoded mix node identifiers used to route the Sphinx packet.
     * @param keys List of the corresponding public keys of the mix nodes in nodelist.
     * @param destination Final destination.
     * @param message Data payload.
     * @return Header and payload of a Sphinx packet encrypted in a nested manner.
     */
    public PacketContent createForwardMessage(byte[][] nodelist, ECPoint[] keys, byte[] destination, byte[] message) throws SphinxException, IOException {
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
        HeaderAndSecrets headerAndSecrets = createHeader(nodelist, keys, finalDestination);

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

        return new PacketContent(headerAndSecrets.sphinxHeader(), delta);
    }

    /**
     * Create a single-use reply block to receive replies anonymously.
     * @param nodelist List of encoded mix node identifiers used to route the Sphinx packet.
     * @param keys List of the corresponding public keys of the mix nodes in nodelist.
     * @param dest Final destination of the Sphinx packet.
     * @return An identifier for the SURB, key tuple to receive a message addressed to this SURB, and the reply block itself.
     */
    public SingleUseReplyBlock createSurb(byte[][] nodelist, ECPoint[] keys, byte[] dest) throws SphinxException, IOException {
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
        HeaderAndSecrets headerAndSecrets = createHeader(nodelist, keys, finalDest);

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
    public PacketContent packageSurb(NymTuple nymTuple, byte[] message) throws SphinxException {
        byte[] zeroes = new byte[params.keyLength()];
        Arrays.fill(zeroes, (byte) 0x00);
        byte[] zeroPaddedMessage = concatenate(zeroes, message);
        byte[] body = padBody(params.bodyLength(), zeroPaddedMessage);
        byte[] delta = params.pi(nymTuple.kTilde(), body);

        return new PacketContent(nymTuple.sphinxHeader(), delta);
    }

    /**
     * Receive a forward Sphinx message.
     * @param macKey Key used to compute the MAC on the payload.
     * @param delta The payload of the Sphinx message.
     * @return Final destination and data payload of the Sphinx message.
     */
    public DestinationAndMessage receiveForward(byte[] macKey, byte[] delta) throws SphinxException {
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
    public byte[] receiveSurb(byte[][] keytuple, byte[] delta) throws SphinxException {
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
    public byte[] packMessageForInstructions(SphinxPacket sphinxPacket) throws SphinxException {

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
    public byte[] packMessage(SphinxPacket sphinxPacket) throws SphinxException {
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
     * Unpack binary message into a SphinxPacket type.
     * @param m Binary message.
     * @return Binary message serialised into SphinxPacket type.
     */
    public SphinxPacket unpackMessage(byte[] m) throws SphinxException, IOException {
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

        PacketContent packetContent = new PacketContent(sphinxHeader, delta);

        return new SphinxPacket(params, packetContent.sphinxHeader(), packetContent.delta());
    }

    /**
     * Compute the maximum number of bytes that can be packet into a single Sphinx packet payload with the given parameters.
     * @return Maximum number of bytes that can be packet into a single Sphinx packet payload with the given parameters.
     */
    public int getMaxPayloadSize() throws SphinxException {
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

    private byte[] padBody(int msgtotalsize, byte[] body) throws SphinxException {
        byte[] initialPadByte = {(byte) 0x7f};
        int numPadBytes = msgtotalsize - (body.length + 1);

        if (numPadBytes < 0) {
            throw new SphinxException("Insufficient space for message");
        }

        byte[] padBytes = new byte[numPadBytes];
        Arrays.fill(padBytes, (byte) 0xff);

        return concatenate(body, initialPadByte, padBytes);
    }

    private byte[] unpadBody(byte[] body) {
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

    public byte[] packECPoint(ECPoint ecPoint) throws SphinxException {
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
