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
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
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

        ECCGroup group = params.getGroup();
        int hops = prefixNodes.length;
        int p = suffixNodeLists.length;
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

        byte[] replicationsharedSecretKey = secrets[hops - 1];


        Pair<byte[][], InstructionPacket[]> bundle = buildSubPackets(params, replicationsharedSecretKey, suffixNodeLists, suffixKeys, destinations, messages);
        byte[][] nextHops = bundle.component1();
        InstructionPacket[] subPackets = bundle.component2();

        if (nextHops.length != subPackets.length) {
            throw new IllegalArgumentException("Each sub-packet must have a corresponding next hop");
        }

        if (p == 0) {
            throw new IllegalArgumentException("At least one sub-packet is required");
        }

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

        int targetSize = params.bodyLength();
        if (payload.length >= targetSize) {
            throw new RuntimeException("payload exceeds allowed size with a length of : " + payload.length);
        }


        int paddingLength = targetSize - payload.length;
        byte[] padding;
        try {
            padding = InstructionEncryptor.padInstructions(params, paddingLength, payload.length, secrets[0], 0);
        } catch (OmniSphinxException e) {
            throw new RuntimeException("[MultiSphinxUtil] Failed to pad instruction block", e);
        }
        payload = SerializationUtils.concatenate(payload, padding);

        byte[][] encryptedMixNodePayloads = new byte[hops][];
        byte[] encryptedPayload = payload;
        for (int i = hops - 1; i >= 0; i--) {
            encryptedPayload = params.xorRho(params.hrho(secrets[i]), encryptedPayload);
            encryptedMixNodePayloads[i] = encryptedPayload;
            System.out.println("encryptedMixNodePayloads[" + i + "] = " + Arrays.toString(encryptedMixNodePayloads[i]));
        }


        byte[][] deltaMACS = new byte[hops][];
        for(int i = 0; i < hops; i++) {
            deltaMACS[i] = params.mac(params.hmu(secrets[i]), encryptedMixNodePayloads[i]);
        }

        byte[] headerLength = SerializationUtils.encodeInt(headerSize);
        byte[] payloadLength = SerializationUtils.encodeInt(payloadSize);
        byte[] nextHopLength = SerializationUtils.encodeInt(nextHopSize);

        byte saltDec = Params.HRHO_SALT;
        byte saltMac = Params.HMU_SALT;

        byte[][] instructions = new byte[hops][];
        for (int i = 0; i < hops; i++) {
            if (i == hops - 1) {
                instructions[i] = MultiSphinxInstructionPresets.createInstructionsMulti(nextHopLength, saltDec,
                        deltaMACS[i], saltMac, (byte) p, payloadLength, headerLength);
            } else {
                instructions[i] = MultiSphinxInstructionPresets.createInstructionsSolo(prefixNodes[i+1], Params.HRHO_SALT, deltaMACS[i], Params.HMU_SALT);
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

        return new InstructionPacket(header, encryptedMixNodePayloads[0]);
    }

    private static Pair<byte[][], InstructionPacket[]> buildSubPackets(Params params, byte[] sharedSecretKey, byte[][][] nodeLists, List<ECPoint[]> keys, byte[][] destinations, byte[][] messages) throws Exception {
        int packetCount = nodeLists.length;
        if (keys.size() != packetCount || destinations.length != packetCount || messages.length != packetCount) {
            throw new IllegalArgumentException("nodeLists, keys, destinations and messages must have the same length");
        }

        byte[][] nextHops = extractNextHops(nodeLists);
        InstructionPacket[] subPackets = new InstructionPacket[packetCount];

        for (int i = 0; i < packetCount; i++) {
            subPackets[i] = createPostReplicationPacket(params, sharedSecretKey, i, nodeLists[i], keys.get(i), destinations[i], messages[i]);
        }

        return new Pair<>(nextHops, subPackets);
    }

    private static InstructionPacket createPostReplicationPacket(Params params, byte[] sharedSecretKey, int counter, byte[][] nodeList, ECPoint[] keys, byte[] destination, byte[] message) throws Exception {
        int hops = nodeList.length;

        if (keys.length != hops) {
            throw new IllegalArgumentException("nodelist/keys length mismatch");
        }

        ECCGroup group = params.getGroup();

        java.math.BigInteger x = group.genSecret();

        ECPoint[] alphas = new ECPoint[hops];
        ECPoint[] sharedSecrets = new ECPoint[hops];
        byte[][] secrets = new byte[hops][];
        for (int i = 0; i < hops; i++) {
            alphas[i] = group.expon(group.getGenerator(), x);
            sharedSecrets[i] = group.expon(keys[i], x);
            secrets[i] = params.getAesKey(sharedSecrets[i]);
            java.math.BigInteger b = params.hb(alphas[i], secrets[i]);
            x = x.multiply(b).mod(group.getOrder());
        }

        byte[] encodedMessage;
        try (MessageBufferPacker packer = MessagePack.newDefaultBufferPacker()) {
            packer.packArrayHeader(1);
            packer.packBinaryHeader(message.length);
            packer.writePayload(message);
            encodedMessage = packer.toByteArray();
        } catch (IOException e) {
            throw new Exception("Failed to encode destination payload", e);
        }
        byte[] initialPad = {(byte) 0x7f};

        byte[] payload = concatenate(encodedMessage, initialPad);



        int targetSize = params.bodyLength();
        if (payload.length >= targetSize) {
            throw new RuntimeException("Instruction block exceeds allowed size");
        }


        int paddingLength = targetSize - payload.length;
        byte[] padding;
        try {
            padding = InstructionEncryptor.padInstructions(params, paddingLength, payload.length, sharedSecretKey, counter);
        } catch (OmniSphinxException e) {
            throw new RuntimeException("Failed to pad instruction block", e);
        }

        byte[][] encryptedMixNodePayloads = new byte[hops][];
        byte[] encryptedPayload = payload;
        for (int i = hops - 1; i >= 0; i--) {
            encryptedPayload = params.xorRho(params.hrho(secrets[i]), encryptedPayload);
            encryptedMixNodePayloads[i] = encryptedPayload;
        }

        byte[][] encryptedMixNodePayloadsWithPadding = new byte[hops][];
        byte[] encryptedPayloadWithPadding = SerializationUtils.concatenate(encryptedMixNodePayloads[0], padding);
        encryptedMixNodePayloadsWithPadding[0] = encryptedPayloadWithPadding;
        for (int i = 1; i < hops; i++) {
            encryptedPayloadWithPadding = params.xorRho(params.hrho(secrets[i]), encryptedPayloadWithPadding);
            encryptedMixNodePayloadsWithPadding[i] = encryptedPayloadWithPadding;
        }

        byte[][] deltaMACS = new byte[hops][];
        for(int i = 0; i < hops; i++) {
            deltaMACS[i] = params.mac(params.hmu(secrets[i]), encryptedMixNodePayloadsWithPadding[i]);
        }

        byte[][] instructions = new byte[hops][];
        for (int i = 0; i < hops - 1; i++) {
            instructions[i] = MultiSphinxInstructionPresets.createInstructionsSolo(nodeList[i+1], Params.HRHO_SALT, deltaMACS[i], Params.HMU_SALT);
        }

        // Final hop exits the mix network towards the destination
        instructions[hops - 1] = MultiSphinxInstructionPresets.createInstructionsSolo(destination, Params.HRHO_SALT, deltaMACS[hops - 1], Params.HMU_SALT);

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

        return new InstructionPacket(header, encryptedMixNodePayloads[0]);
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