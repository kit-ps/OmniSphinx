package javasphinx.packet;

import javasphinx.packet.header.PacketContent;
import org.msgpack.core.MessagePack;

import java.io.IOException;

/**
 * Type to represent the return value of the mix node processing method
 */
public record ProcessedPacket(byte[] tag, byte[] routing, PacketContent packetContent, byte[] macKey) {

    public RoutingFlag routingFlag() throws IOException {
        final var unpacker = MessagePack.newDefaultUnpacker(routing);
        int routingLen = unpacker.unpackArrayHeader();
        String flag = unpacker.unpackString();
        unpacker.close();
        return RoutingFlag.byValue(flag);
    }

    public RelayInfo relayInfo() throws IOException {
        final var unpacker = MessagePack.newDefaultUnpacker(routing);
        int routingLen = unpacker.unpackArrayHeader();
        String flag = unpacker.unpackString();
        final var routingFlag = RoutingFlag.byValue(flag);
        if (!RoutingFlag.RELAY.equals(routingFlag)) {
            throw new IllegalStateException("Tried to extract relayInfo on a packet that should not be relayed!");
        }
        final var id = unpacker.unpackInt();
        final var additionalInfo = unpacker.unpackInt();
        unpacker.close();
        return new RelayInfo(id, additionalInfo);
    }
}
