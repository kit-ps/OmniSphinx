package javasphinx.packet;

import javasphinx.SphinxParams;
import javasphinx.packet.header.PacketContent;

import java.util.Objects;

/**
 * Type used to represent the Sphinx packet as it is encoded into a binary format
 */
public final class SphinxPacket {
    private final int headerLength;
    private final int bodyLength;
    private final PacketContent packetContent;

    /**
     *
     */
    public SphinxPacket(SphinxParams params, PacketContent packetContent) {
        this.headerLength = params.headerLength();
        this.bodyLength = params.bodyLength();
        this.packetContent = packetContent;
    }

    public int headerLength() {
        return headerLength;
    }

    public int bodyLength() {
        return bodyLength;
    }

    public PacketContent packetContent() {
        return packetContent;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (SphinxPacket) obj;
        return this.headerLength == that.headerLength && this.bodyLength == that.bodyLength &&
                Objects.equals(this.packetContent, that.packetContent);
    }

    @Override
    public int hashCode() {
        return Objects.hash(headerLength, bodyLength, packetContent);
    }

    @Override
    public String toString() {
        return "SphinxPacket[" +
                "headerLength=" + headerLength + ", " +
                "bodyLength=" + bodyLength + ", " +
                "packetContent=" + packetContent + ']';
    }

}
