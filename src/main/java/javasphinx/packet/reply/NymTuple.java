package javasphinx.packet.reply;

import javasphinx.packet.header.SphinxHeader;

/**
 * Class to represent the reply block used for replying to anonymous recipients
 */
public record NymTuple(byte[] node, SphinxHeader sphinxHeader, byte[] kTilde) {
}
