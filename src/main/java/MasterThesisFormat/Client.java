package MasterThesisFormat;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.VM.VMUtil;
import MasterThesisFormat.instruction.Instruction;
import MasterThesisFormat.instruction.SphinxInstructionPresets;
import MasterThesisFormat.routing.RoutingStrategy;
import javasphinx.SphinxClient;
import javasphinx.SphinxException;
import javasphinx.packet.RoutingFlag;
import javasphinx.packet.header.SphinxPacketContent;
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
     * Select a subset of mix node identifiers according to the Client's {@link RoutingStrategy}
     * @param identifiers list of mix node ids
     * @param mixCount count of ids to select from identifiers
     * @return mix identifiers
     */
    public int[] route(int[] identifiers, int mixCount) throws Exception {
        if (identifiers.length < mixCount) {
            throw new Exception("Number of possible elements (%d) was less than the requested number (%d)"
                    .formatted(identifiers.length, mixCount));
        }
        return routingStrategy.route(identifiers, mixCount);
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
     * Create a forward instruction Sphinx packet.
     * @param nodelist List of encoded mix node identifiers used to route the packet.
     * @param keys List of the corresponding public keys of the mix nodes in nodelist.
     * @param destination Final destination.
     * @param message Data payload.
     * @return Header and payload of a Sphinx packet encrypted in a nested manner.
     */
    public InstructionPacket createSphinxInstructionPacket(byte[][] nodelist, ECPoint[] keys, byte[] destination, byte[] message) throws SphinxException, IOException {
        SphinxPacketContent sphinxPacketContent = SphinxClient.createForwardMessage(nodelist, keys, destination, message, params);
        byte[][] secrets = sphinxPacketContent.headerAndSecrets().secrets();

        byte[] encryptedInstructions = params.pi(params.hpi(secrets[nodelist.length - 1]),
                SphinxInstructionPresets.createInstructions((byte) sphinxPacketContent.headerAndSecrets().alpha()[nodelist.length - 1].getEncoded(false).length,
                (byte) sphinxPacketContent.headerAndSecrets().sphinxHeader().getBeta().length,
                (byte) params.keyLength()));

        for (int i = nodelist.length - 2; i >= 0; i--) {
            byte[] instructions = params.pi(params.hpi(secrets[i]),
                    SphinxInstructionPresets.createInstructions((byte) sphinxPacketContent.headerAndSecrets().alpha()[i].getEncoded(false).length,
                            (byte) sphinxPacketContent.headerAndSecrets().sphinxHeader().getBeta().length,
                            (byte) params.keyLength()));
            encryptedInstructions = VMUtil.concatenate(params.pi(params.hpi(secrets[i]), encryptedInstructions), encryptedInstructions);
        }

        return null;
    }

}
