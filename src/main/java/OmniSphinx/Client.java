package OmniSphinx;

import OmniSphinx.InstructionPacket.InstructionPacket;
import OmniSphinx.MixFormats.Sphinx.SphinxUtil;
import OmniSphinx.header.InstructionHeader;
import OmniSphinx.routing.RoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;

import java.io.IOException;


public class Client {
    public static final int MAX_INSTRUCTION_SIZE = 1024;

    private final Params params;
    private final RoutingStrategy routingStrategy;


    public Client(Params params, RoutingStrategy routingStrategy) {
        this.params = params;
        this.routingStrategy = routingStrategy;
    }

    public Params getParams() {
        return params;
    }

    public RoutingStrategy getRoutingStrategy() {
        return routingStrategy;
    }


    /**
     * Create a forward instruction Sphinx packet.
     * @param nodelist List of encoded mix node identifiers used to route the packet.
     * @param keys List of the corresponding public keys of the mix nodes in nodelist.
     * @param destination Final destination.
     * @param message Data payload.
     * @return Header and payload of a Sphinx packet encrypted in a nested manner.
     */
    public InstructionPacket createSphinxInstructionPacket(byte[][] nodelist, ECPoint[] keys, byte[] destination, byte[] message) throws Exception {
        return SphinxUtil.createSphinxInstructionPacket(params, nodelist, keys, destination, message);
    }


    /**
     * Layout:
     * [alpha | encrypted instructions | MAC | payload]
     *
     */
    public byte[] packInstructionPacket(InstructionPacket packet) throws Exception {
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

