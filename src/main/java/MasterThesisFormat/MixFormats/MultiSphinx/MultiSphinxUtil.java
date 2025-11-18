package MasterThesisFormat.MixFormats.MultiSphinx;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.OmniSphinxException;
import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import MasterThesisFormat.crypto.ECCGroup;
import MasterThesisFormat.header.InstructionEncryptor;
import MasterThesisFormat.header.InstructionHeader;
import MasterThesisFormat.MixFormats.Sphinx.SphinxInstructionPresets;
import MasterThesisFormat.MixFormats.Sphinx.SphinxUtil;
import kotlin.Pair;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import static MasterThesisFormat.SerializationUtils.concatenate;

public class MultiSphinxUtil {

    public static InstructionPacket createMultiSphinxPacket(Params params, byte[][] prefixNodes, ECPoint[] prefixKeys, List<byte[][]> suffixPaths, List<ECPoint[]> suffixKeys, byte[][] messages, byte[][] destinations) throws Exception {
        if (prefixNodes.length != prefixKeys.length) {
            throw new IllegalArgumentException("prefixNodes and prefixKeys must have the same length");
        }
        if (suffixPaths.size() != suffixKeys.size() || suffixPaths.size() != messages.length || suffixPaths.size() != destinations.length) {
            throw new IllegalArgumentException("suffix path, key, destination and message counts must match");
        }
        if (prefixNodes.length == 0) {
            throw new IllegalArgumentException("At least one prefix hop (the replication node) is required");
        }


        byte[][][] suffixNodeLists = suffixPaths.toArray(new byte[0][][]);

        Pair<byte[][], InstructionPacket[]> bundle = buildSubPackets(params, suffixNodeLists, suffixKeys, destinations, messages);
        return createMultiSphinxPacket(params, prefixNodes, prefixKeys, bundle.component1(), bundle.component2());
    }

    private static Pair<byte[][], InstructionPacket[]> buildSubPackets(Params params, byte[][][] nodeLists, List<ECPoint[]> keys, byte[][] destinations, byte[][] messages) throws Exception {
        int packetCount = nodeLists.length;
        if (keys.size() != packetCount || destinations.length != packetCount || messages.length != packetCount) {
            throw new IllegalArgumentException("nodeLists, keys, destinations and messages must have the same length");
        }

        byte[][] nextHops = extractNextHops(nodeLists);
        InstructionPacket[] subPackets = new InstructionPacket[packetCount];

        for (int i = 0; i < packetCount; i++) {
            subPackets[i] = SphinxUtil.createSphinxInstructionPacket(params, nodeLists[i], keys.get(i), destinations[i], messages[i]);
        }

        return new Pair<>(nextHops, subPackets);
    }



    private static InstructionPacket createMultiSphinxPacket(Params params, byte[][] prefixNodes, ECPoint[] prefixKeys, byte[][] nextHops, InstructionPacket[] subPackets) throws Exception {
        if (nextHops.length != subPackets.length) {
            throw new IllegalArgumentException("Each sub-packet must have a corresponding next hop");
        }

        int p = subPackets.length;
        if (p == 0) {
            throw new IllegalArgumentException("At least one sub-packet is required");
        }

        ECCGroup group = params.getGroup();
        int hops = prefixNodes.length;
        if (hops != prefixKeys.length || hops == 0) {
            throw new IllegalArgumentException("prefixNodes and prefixKeys must have the same non-zero length");
        }

        BigInteger x = group.genSecret();

        ECPoint[] alphas = new ECPoint[hops];
        byte[][] secrets = new byte[hops][];
        for (int i = 0; i < hops; i++) {
            alphas[i] = group.expon(group.getGenerator(), x);
            ECPoint sharedSecret = group.expon(prefixKeys[i], x);
            secrets[i] = params.getAesKey(sharedSecret);
            BigInteger b = params.hb(alphas[i], secrets[i]);
            x = x.multiply(b).mod(group.getOrder());
        }

        byte[] sharedSecretKey = secrets[hops - 1];

        byte[][] headers = new byte[p][];
        byte[][] payloads = new byte[p][];
        for (int i = 0; i < p; i++) {
            headers[i] = encodeHeader(subPackets[i].getHeader());
            payloads[i] = subPackets[i].getPayload();
        }

        int headerSize = headers[0].length;
        int payloadSize = payloads[0].length;
        int nextHopSize = nextHops[0].length;

        for (int i = 1; i < p; i++) {
            if (headers[i].length != headerSize) {
                throw new IllegalArgumentException("All sub-packets must have the same header length");
            }
            if (payloads[i].length != payloadSize) {
                throw new IllegalArgumentException("All sub-packets must have the same payload length");
            }
            if (nextHops[i].length != nextHopSize) {
                throw new IllegalArgumentException("All next hops must have the same length");
            }
        }

        byte[] payload = buildPayload(headers, payloads, nextHops);

        byte[] encryptedPayload = params.xorRho(params.hrho(sharedSecretKey), payload);
        byte[] payloadMac = params.mac(params.hmu(sharedSecretKey), encryptedPayload);

        byte[] headerLength = SerializationUtils.encodeInt(headerSize);
        byte[] payloadLength = SerializationUtils.encodeInt(payloadSize);
        byte[] nextHopLength = SerializationUtils.encodeInt(nextHopSize);

        byte saltDec = Params.HRHO_SALT;
        byte saltMac = Params.HMU_SALT;

        byte[][] instructions = new byte[hops][];
        for (int i = 0; i < hops; i++) {
            if (i == hops - 1) {
                instructions[i] = MultiSphinxInstructionPresets.createInstructionsMulti(nextHopLength, saltDec,
                        payloadMac, saltMac, (byte) p, payloadLength, headerLength);
            } else {
                instructions[i] = SphinxInstructionPresets.createInstructions(prefixNodes[i + 1], Params.HPI_SALT);
            }
        }

        int headerLen = 0;
        for (byte[] instruction : instructions) {
            headerLen += instruction.length + params.keyLength();
        }

        int instPadLen = params.getInstructionTotalSize() - headerLen + params.keyLength();
        if (instPadLen < 0) {
            throw new OmniSphinxException("Header to small!");
        }

        byte[] randomPad = new byte[instPadLen];
        new java.security.SecureRandom().nextBytes(randomPad);

        instructions[hops - 1] = concatenate(instructions[hops - 1], randomPad);

        byte[] onion = InstructionEncryptor.encryptFixedSize(params, instructions, secrets,
                params.getInstructionTotalSize());

        byte[] finalMac = params.mac(params.hmu(secrets[0]), onion);

        InstructionHeader header = new InstructionHeader(alphas[0], onion, finalMac);

        return new InstructionPacket(header, encryptedPayload);
    }

    private static byte[][] extractNextHops(byte[][][] nodeLists) {
        byte[][] nextHops = new byte[nodeLists.length][];
        for (int i = 0; i < nodeLists.length; i++) {
            if (nodeLists[i].length == 0) {
                throw new IllegalArgumentException("Each node list must contain at least one hop");
            }
            nextHops[i] = nodeLists[i][0];
        }
        return nextHops;
    }

    private static byte[] buildPayload(byte[][] headers, byte[][] payloads, byte[][] nextHops) throws IOException {
        int p = headers.length;
        ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();
        for (int i = 0; i < p; i++) {
            payloadStream.write(headers[i]);
            payloadStream.write(payloads[i]);
            payloadStream.write(nextHops[i]);
        }
        return payloadStream.toByteArray();
    }

    private static byte[] encodeHeader(InstructionHeader header) {
        return concatenate(SerializationUtils.encodeECPoint(header.getAlpha()),
                header.getInstructions(),
                header.getMAC());
    }
}