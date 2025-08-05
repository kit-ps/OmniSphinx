package MasterThesisFormat;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.VM.VM;
import MasterThesisFormat.VM.VMContext;
import MasterThesisFormat.VM.VMException;
import MasterThesisFormat.VM.VMOutput;
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
     * [len(instructions) | instructions for this hop | MAC | remaining instructions]
     */
    public List<InstructionPacket> process(byte[] rawPacket) throws VMException {
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

        byte[] plainInstr;
        try {
            plainInstr = params.xorRho(params.hrho(aesKey), encInstr);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt instructions", e);
        }

        byte[] expectedMac = params.mu(params.hmu(aesKey), plainInstr);
        if (!Arrays.equals(expectedMac, mac)) {
            throw new RuntimeException("Instruction MAC mismatch");
        }

        //compute blinding factors
        BigInteger b = params.hb(alpha, aesKey);

        //Blinding
        alpha = params.getGroup().expon(alpha, b);


        HashMap<Byte, byte[]> register = new HashMap<>();
        register.put(InstructionRegister.NEXT_ALPHA.getCode(), alpha.getEncoded(true));
        register.put(InstructionRegister.INSTRUCTIONS.getCode(), plainInstr);
        register.put(InstructionRegister.MAC.getCode(), mac);
        register.put(InstructionRegister.PAYLOAD.getCode(), packetRaw);
        VMContext vmContext = new VMContext(register);
        List<VMOutput> outputs = vm.interpret(vmContext);

        List<InstructionPacket> packets = new ArrayList<>();
        for (VMOutput out : outputs) {
            ECPoint nextAlpha = SerializationUtils.decodeECPoint(out.getNextAlpha());
            InstructionHeader header = new InstructionHeader(nextAlpha, out.getInstructions(), out.getMAC());
            InstructionPacket packet = new InstructionPacket(header, out.getOutgoingPayload());
            packets.add(packet);
            sendToNextNode(out.getNextHop(), packet);
        }

        return packets;
    }

    private void sendToNextNode(byte[] nextHop, InstructionPacket packet) {
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

}
