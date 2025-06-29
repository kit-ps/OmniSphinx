package MasterThesisFormat;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.VM.VMUtil;
import MasterThesisFormat.header.InstructionHeader;
import MasterThesisFormat.instruction.Instruction;
import MasterThesisFormat.instruction.SphinxInstructionPresets;
import MasterThesisFormat.routing.RoutingStrategy;
import javasphinx.SphinxClient;
import javasphinx.SphinxException;
import javasphinx.packet.RoutingFlag;
import javasphinx.packet.SphinxPacket;
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
    public InstructionPacket createSphinxInstructionPacket(byte[][] nodelist, ECPoint[] keys, byte[] destination, byte[] message) throws Exception, IOException {
        SphinxPacketContent content = SphinxClient.createForwardMessage(nodelist, keys, destination, message, params);

        byte[][] secrets = content.headerAndSecrets().secrets();
        ECPoint[] alphas = content.headerAndSecrets().alpha();

        byte[] onion = new byte[0];
        byte[] sigma = new byte[params.keyLength()];

        for (int i = nodelist.length - 1; i >= 0; i--) {
            byte[] instr = SphinxInstructionPresets.createInstructions(
                    (byte) alphas[i].getEncoded(false).length,
                    (byte) content.headerAndSecrets().sphinxHeader().getBeta().length,
                    (byte) params.keyLength());

            int plainLen = instr.length + onion.length;
            if (plainLen + params.keyLength() > MAX_INSTRUCTION_SIZE) {
                throw new SphinxException("Instructions exceed maximum size");
            }

            byte[] plain = new byte[plainLen];
            System.arraycopy(instr, 0, plain, 0, instr.length);
            System.arraycopy(onion, 0, plain, instr.length, onion.length);

            byte[] enc = params.xorRho(params.hrho(secrets[i]), plain);
            sigma = params.mu(params.hmu(secrets[i]), plain);

            onion = new byte[sigma.length + enc.length];
            System.arraycopy(sigma, 0, onion, 0, sigma.length);
            System.arraycopy(enc, 0, onion, sigma.length, enc.length);
        }

        byte[] finalSigma = VMUtil.slice(onion, 0, params.keyLength());
        byte[] finalOnion = VMUtil.slice(onion, params.keyLength(), onion.length);

        InstructionHeader header = new InstructionHeader(alphas[0], finalSigma, finalOnion);

        SphinxPacket packet = new SphinxPacket(params, content.headerAndSecrets().sphinxHeader(), content.delta());

        return new InstructionPacket(header, packet);
    }
}

