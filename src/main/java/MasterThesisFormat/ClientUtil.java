package MasterThesisFormat;

import MasterThesisFormat.routing.RoutingStrategy;
import javasphinx.packet.RoutingFlag;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;

import java.io.IOException;

public class ClientUtil {

    /**
     * Encode the mix node nextNodeId into binary format.
     * @param idnum Identifier of the mix node.
     * @param additionalInfo packet identifier, the first mix uses this to route reply packets
     * @return Identifier of the mix node in binary format.
     */
    public static byte[] encodeNode(int idnum, int additionalInfo) throws Exception {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();

        try {
            // This is NOT specific to the string, this is the amount of 2 byte values following, regardless of type!!!
            packer.packArrayHeader(3);
            packer.packString(RoutingFlag.RELAY.value()); //2 bytes
            packer.packInt(idnum); //2 bytes
            packer.packInt(additionalInfo); //2 bytes
            packer.close();
        } catch (IOException ex) {
            throw new Exception("Failed to encode node");
        }

        return packer.toByteArray();
    }

    /**
     * Select a subset of mix node identifiers according to the Client's {@link RoutingStrategy}
     * @param identifiers list of mix node ids
     * @param mixCount count of ids to select from identifiers
     * @return mix identifiers
     */
    public static int[] route(int[] identifiers, int mixCount, RoutingStrategy strategy) throws Exception {
        if (identifiers.length < mixCount) {
            throw new Exception("Number of possible elements (%d) was less than the requested number (%d)"
                    .formatted(identifiers.length, mixCount));
        }
        return strategy.route(identifiers, mixCount);
    }
}
