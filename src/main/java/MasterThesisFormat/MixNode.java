package MasterThesisFormat;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.InstructionPacket.InstructionPacketAndNextHop;
import MasterThesisFormat.MixFormats.Sphinx.SphinxInstructionPresets;
import MasterThesisFormat.VM.*;
import MasterThesisFormat.header.InstructionHeader;
import MasterThesisFormat.instruction.InstructionRegister;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import okhttp3.*;
import org.bouncycastle.math.ec.ECPoint;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static MasterThesisFormat.MixFormats.Sphinx.SphinxUtil.toHex;

public class MixNode {
    private final BigInteger secret;
    private final Params params;
    private final VM vm;
    private final byte[] id;
    private HttpServer server;
    private final OkHttpClient httpClient = new OkHttpClient();


    public MixNode(byte[] id, BigInteger secret, Params params) throws IOException {
        this.id = id.clone();
        this.secret = secret;
        this.params = params;
        this.vm = new VM(secret, params);

        URI uri = URI.create(new String(id, StandardCharsets.UTF_8));
        int port = uri.getPort();
        if (port == -1) {
            port = uri.getScheme().equalsIgnoreCase("https") ? 443 : 80;
        }
        startListener(port);
    }

    public byte[] getId() {
        return id.clone();
    }

    public void startListener(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new PacketHandler());
        server.setExecutor(null);
        server.start();
    }

    public void stopListener() {
        if (server != null) {
            server.stop(0);
        }
    }

    private class PacketHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            byte[] data = exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, 0);
            exchange.getResponseBody().close();
            try {
                process(data);
            } catch (VMException e) {
                throw new IOException("Failed to process packet", e);
            }
        }
    }

    /**
     * layout: [alpha | encrypted instructions | MAC | packet]
     * Encrypted instructions layout:
     * [instructions for this hop (terminated with STOP) | MAC | remaining instructions]
     */
    public List<InstructionPacket> process(byte[] rawPacket) throws VMException {
        System.out.println("[MixNode] Processing raw packet, length=" + rawPacket.length);
        //System.out.println("[MixNode] Raw packet bytes: " + toHex(rawPacket));
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(rawPacket);
        byte[] encodedAlpha, encInstr, mac, packetRaw;
        try {
            int arrLen = unpacker.unpackArrayHeader();
            if (arrLen != 4) {
                throw new IllegalArgumentException("Invalid instruction packet layout");
            }
            encodedAlpha = unpacker.readPayload(unpacker.unpackBinaryHeader());
            encInstr = unpacker.readPayload(unpacker.unpackBinaryHeader());
            mac = unpacker.readPayload(unpacker.unpackBinaryHeader());
            packetRaw = unpacker.readPayload(unpacker.unpackBinaryHeader());
            unpacker.close();
        } catch (java.io.IOException e) {
            throw new RuntimeException("Failed to unpack instruction packet", e);
        }

        System.out.println("[MixNode] Encoded alpha length=" + encodedAlpha.length + ", bytes=" + toHex(encodedAlpha));
        //System.out.println("[MixNode] Encrypted instructions length=" + encInstr.length + ", bytes=" + toHex(encInstr));
        System.out.println("[MixNode] MAC length=" + mac.length + ", bytes=" + toHex(mac));
        System.out.println("[MixNode] Payload length=" + packetRaw.length + ", bytes=" + toHex(packetRaw));

        //Preprocessing
        ECPoint alpha = SerializationUtils.decodeECPoint(encodedAlpha);
        System.out.println("[MixNode] Decoded alpha (compressed): " + toHex(alpha.getEncoded(true)));

        ECPoint sharedSecret  = params.getGroup().expon(alpha, secret);
        System.out.println("[MixNode] Shared secret (compressed): " + toHex(sharedSecret.getEncoded(true)));

        byte[] aesKey = params.getAesKey(sharedSecret);
        System.out.println("[MixNode] Derived AES key: " + toHex(aesKey));

        InstructionLayer layer = decryptInstructionLayer(encInstr, aesKey, mac);

        //compute blinding factors
        BigInteger b = params.hb(alpha, aesKey);
        System.out.println("[MixNode] Blinding factor b: " + toHex(b.toByteArray()));

        //Blinding
        alpha = params.getGroup().expon(alpha, b);
        System.out.println("[MixNode] Blinded alpha (compressed): " + toHex(alpha.getEncoded(true)));


        HashMap<Byte, byte[]> register = new HashMap<>();
        register.put(InstructionRegister.NEXT_ALPHA.getCode(), alpha.getEncoded(true));
        register.put(InstructionRegister.INSTRUCTIONS.getCode(), layer.instructions());
        register.put(InstructionRegister.NEXT_INSTRUCTIONS.getCode(), layer.nextInstructions());
        register.put(InstructionRegister.MAC.getCode(), layer.mac());
        register.put(InstructionRegister.PAYLOAD.getCode(), packetRaw);
        register.put(InstructionRegister.SHARED_SECRET.getCode(), sharedSecret.getEncoded(true));
        VMContext vmContext = new VMContext(register);
        List<VMOutput> outputs = vm.interpret(vmContext);

        List<InstructionPacket> packets = new ArrayList<>();
        for (VMOutput out : outputs) {
            ECPoint nextAlpha = SerializationUtils.decodeECPoint(out.getNextAlpha());
            InstructionHeader header = new InstructionHeader(nextAlpha, out.getInstructions(), out.getMAC());
            InstructionPacket packet = new InstructionPacket(header, out.getOutgoingPayload());
            System.out.println("[MixNode] VM output next hop=" + new String(out.getNextHop(), StandardCharsets.UTF_8));
            System.out.println("[MixNode] VM output alpha (compressed): " + toHex(nextAlpha.getEncoded(true)));
            //System.out.println("[MixNode] VM output instructions: " + toHex(out.getInstructions()));
            System.out.println("[MixNode] VM output MAC: " + toHex(out.getMAC()));
            //System.out.println("[MixNode] VM output payload length=" + out.getOutgoingPayload().length + ", bytes=" + toHex(out.getOutgoingPayload()));
            packets.add(packet);
            sendToNextNode(out.getNextHop(), packet);
        }

        return packets;
    }

    protected void sendToNextNode(byte[] nextHop, InstructionPacket packet) {
        String url = new String(nextHop, StandardCharsets.UTF_8);
        byte[] data;
        try {
            data = packInstructionPacket(packet);
        } catch (Exception e) {
            throw new RuntimeException("Failed to pack instruction packet", e);
        }

        RequestBody body = RequestBody.create(data, MediaType.parse("application/octet-stream"));
        Request request = new Request.Builder().url(url).post(body).build();
        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Failed to send packet: HTTP " + response.code());
            }
        } catch (IOException ex) {
            throw new RuntimeException("Error forwarding packet", ex);
        }
    }

    private byte[] packInstructionPacket(InstructionPacket packet) throws Exception {
        InstructionHeader header = packet.getHeader();

        byte[] encodedAlpha = SerializationUtils.encodeECPoint(header.getAlpha());
        byte[] instructions = header.getInstructions();
        byte[] mac = header.getMAC();
        byte[] payload = packet.getPayload();

        System.out.println("[MixNode] Packing instruction packet");
        System.out.println("[MixNode] Alpha (compressed) length=" + encodedAlpha.length + ", bytes=" + toHex(encodedAlpha));
        System.out.println("[MixNode] Instructions length=" + instructions.length + ", bytes=" + toHex(instructions));
        System.out.println("[MixNode] MAC length=" + mac.length + ", bytes=" + toHex(mac));
        System.out.println("[MixNode] Payload length=" + payload.length + ", bytes=" + toHex(payload));

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(4);
            packer.packBinaryHeader(encodedAlpha.length);
            packer.writePayload(encodedAlpha);
            packer.packBinaryHeader(instructions.length);
            packer.writePayload(instructions);
            packer.packBinaryHeader(mac.length);
            packer.writePayload(mac);
            packer.packBinaryHeader(payload.length);
            packer.writePayload(payload);
            packer.close();
        } catch (IOException ex) {
            throw new Exception("Failed to pack instruction packet");
        }

        return packer.toByteArray();
    }

    public List<InstructionPacketAndNextHop> processInstructionPacketAndNextHop(byte[] rawPacket) throws VMException {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(rawPacket);
        byte[] encodedAlpha, encInstr, mac, packetRaw;
        try {
            int arrLen = unpacker.unpackArrayHeader();
            if (arrLen != 4) {
                throw new IllegalArgumentException("Invalid instruction packet layout");
            }
            encodedAlpha = unpacker.readPayload(unpacker.unpackBinaryHeader());
            encInstr = unpacker.readPayload(unpacker.unpackBinaryHeader());
            mac = unpacker.readPayload(unpacker.unpackBinaryHeader());
            packetRaw = unpacker.readPayload(unpacker.unpackBinaryHeader());
            unpacker.close();
        } catch (java.io.IOException e) {
            throw new RuntimeException("Failed to unpack instruction packet", e);
        }

        //Preprocessing
        ECPoint alpha = SerializationUtils.decodeECPoint(encodedAlpha);

        ECPoint sharedSecret  = params.getGroup().expon(alpha, secret);

        byte[] aesKey = params.getAesKey(sharedSecret);

        InstructionLayer layer = decryptInstructionLayer(encInstr, aesKey, mac);

        //compute blinding factors
        BigInteger b = params.hb(alpha, aesKey);

        //Blinding
        alpha = params.getGroup().expon(alpha, b);


        HashMap<Byte, byte[]> register = new HashMap<>();
        register.put(InstructionRegister.NEXT_ALPHA.getCode(), alpha.getEncoded(true));
        register.put(InstructionRegister.INSTRUCTIONS.getCode(), layer.instructions());
        register.put(InstructionRegister.NEXT_INSTRUCTIONS.getCode(), layer.nextInstructions());
        register.put(InstructionRegister.MAC.getCode(), layer.mac());
        register.put(InstructionRegister.PAYLOAD.getCode(), packetRaw);
        VMContext vmContext = new VMContext(register);
        List<VMOutput> outputs = vm.interpret(vmContext);

        List<InstructionPacketAndNextHop> packets = new ArrayList<>();
        for (VMOutput out : outputs) {
            ECPoint nextAlpha = SerializationUtils.decodeECPoint(out.getNextAlpha());
            InstructionHeader header = new InstructionHeader(nextAlpha, out.getInstructions(), out.getMAC());
            InstructionPacket packet = new InstructionPacket(header, out.getOutgoingPayload());
            InstructionPacketAndNextHop instructionPacketAndNextHop = new InstructionPacketAndNextHop(out.getNextHop(), packet);
            packets.add(instructionPacketAndNextHop);
        }

        return packets;
    }

    private InstructionLayer decryptInstructionLayer(byte[] encInstr, byte[] aesKey, byte[] mac) {
        byte[] hrhoKey;
        try {
            hrhoKey = params.hrho(aesKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive hrho key", e);
        }

        System.out.println("[MixNode] Decrypting instruction layer");
        System.out.println("[MixNode] Encrypted instructions: " + toHex(encInstr));
        System.out.println("[MixNode] AES key: " + toHex(aesKey));
        System.out.println("[MixNode] hrho key: " + toHex(hrhoKey));

        byte[] plain;
        try {
            plain = params.xorRho(hrhoKey, encInstr);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt instructions", e);
        }

        byte[] hmuKey = params.hmu(aesKey);
        byte[] expectedMac = params.mac(hmuKey, encInstr);
        System.out.println("[MixNode] hmu key: " + toHex(hmuKey));
        System.out.println("[MixNode] Provided MAC: " + toHex(mac));
        System.out.println("[MixNode] Expected MAC: " + toHex(expectedMac));
        if (!Arrays.equals(expectedMac, mac)) {
            throw new RuntimeException("Instruction MAC mismatch");
        }

        int instructionsEnd = VMUtil.findInstructionsEnd(plain);
        int macLen = params.keyLength();


        byte[] instructions = Arrays.copyOfRange(plain, 0, instructionsEnd);
        byte[] nextMac = Arrays.copyOfRange(plain, instructionsEnd, instructionsEnd + macLen);

        int offset = instructionsEnd + macLen;
        System.out.println("WICHTIG INSTRUCTIONS ENDS AT: " + offset);

        byte[] zeros = new byte[offset];
        Arrays.fill(zeros, (byte) 0x00);
        byte[] paddedBeta = SerializationUtils.concatenate(encInstr, zeros);
        byte[] prg;
        try {
            prg = params.xorRho(hrhoKey, paddedBeta);
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive next instruction layer", e);
        }

        byte[] nextInstructions = Arrays.copyOfRange(prg, offset, prg.length);
        byte[] encryptedZeros = Arrays.copyOfRange(prg, encInstr.length, paddedBeta.length);
        System.out.println("WICHTIG MIXNODE ENCRYPTED ZEROS: " + toHex(encryptedZeros));
        //System.out.println("[MixNode] Plain instructions length=" + instructions.length + ", bytes=" + toHex(instructions));
        //System.out.println("[MixNode] Next MAC length=" + nextMac.length + ", bytes=" + toHex(nextMac));
        //System.out.println("[MixNode] Next instructions length=" + nextInstructions.length + ", bytes=" + toHex(nextInstructions));
        return new InstructionLayer(instructions, nextMac, nextInstructions);
    }

    private static final class InstructionLayer {
        private final byte[] instructions;
        private final byte[] mac;
        private final byte[] nextInstructions;

        private InstructionLayer(byte[] instructions, byte[] mac, byte[] nextInstructions) {
            this.instructions = instructions;
            this.mac = mac;
            this.nextInstructions = nextInstructions;
        }

        private byte[] instructions() {
            return instructions.clone();
        }

        private byte[] mac() {
            return mac.clone();
        }

        private byte[] nextInstructions() {
            return nextInstructions.clone();
        }
    }

}
