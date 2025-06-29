package javasphinx.packet;

import MasterThesisFormat.MixFormats.Packet;
import javasphinx.SphinxParams;
import javasphinx.packet.header.SphinxHeader;
import javasphinx.packet.header.SphinxPacketContent;

import java.util.Arrays;
import java.util.Objects;

/**
 * Type used to represent the Sphinx packet as it is encoded into a binary format
 */
public final class SphinxPacket extends Packet {
    private final int headerLength;
    private final int bodyLength;
    private final SphinxHeader sphinxHeader;
    private final byte[] delta;

    /**
     *
     */
    public SphinxPacket(SphinxParams params, SphinxHeader sphinxHeader, byte[] delta) {
        this.headerLength = params.headerLength();
        this.bodyLength = params.bodyLength();
        this.sphinxHeader = sphinxHeader;
        this.delta = delta;
    }

    public SphinxPacketContent getPacketContet() {
        return new SphinxPacketContent(sphinxHeader, delta);
    }

    public int headerLength() {
        return headerLength;
    }

    public int bodyLength() {
        return bodyLength;
    }

    public SphinxHeader getHeader() {
        return sphinxHeader;
    }

    public byte[] getDelta() {
        return delta;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        var that = (SphinxPacket) obj;
        return this.headerLength == that.headerLength && this.bodyLength == that.bodyLength &&
                Objects.equals(this.sphinxHeader, that.sphinxHeader) && Arrays.equals(this.delta, that.delta);
    }

    @Override
    public int hashCode() {
        return Objects.hash(headerLength, bodyLength, sphinxHeader, Arrays.hashCode(delta));
    }

    @Override
    public String toString() {
        return "SphinxPacket[" +
                "headerLength=" + headerLength + ", " +
                "bodyLength=" + bodyLength + ", " +
                "header=" + sphinxHeader +
                "delta=" + Arrays.toString(delta) + ']';
    }

}
