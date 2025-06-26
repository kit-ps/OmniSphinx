package javasphinx.packet.header;

/**
 * Type to combine Sphinx header and secrets used to encrypt the Sphinx payload
 */
public record HeaderAndSecrets(Header header, byte[][] secrets) {
}
