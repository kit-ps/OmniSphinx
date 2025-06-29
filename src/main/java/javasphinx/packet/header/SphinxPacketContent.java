package javasphinx.packet.header;

/**
 * Type to combine Sphinx header and payload
 */
public record SphinxPacketContent(HeaderAndSecrets headerAndSecrets, byte[] delta) {
}
