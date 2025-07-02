package javasphinx.packet.header;

/**
 * Type to combine Sphinx header and payload
 */
public record SphinxPacketContent(SphinxHeader header, byte[] delta) {
}
