package javasphinx.packet.reply;

/**
 * Type to combine a reply block and the related information
 */
public record SingleUseReplyBlock(byte[] xid, byte[][] keyTuple, NymTuple nymTuple) {
}
