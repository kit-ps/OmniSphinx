package javasphinx.packet.header;

/**
 * Type to combine Sphinx header and payload
 */
public record PacketContent(Header header, byte[] delta) {
}
