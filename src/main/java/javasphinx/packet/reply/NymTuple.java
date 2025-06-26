package javasphinx.packet.reply;

import javasphinx.packet.header.Header;

/**
 * Class to represent the reply block used for replying to anonymous recipients
 */
public record NymTuple(byte[] node, Header header, byte[] kTilde) {
}
