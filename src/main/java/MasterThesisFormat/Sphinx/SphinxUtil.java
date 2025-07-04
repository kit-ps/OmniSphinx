package MasterThesisFormat.Sphinx;

import MasterThesisFormat.Params;
import javasphinx.crypto.ECCGroup;
import org.bouncycastle.math.ec.ECPoint;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import static MasterThesisFormat.SerializationUtils.concatenate;

public final class SphinxUtil {
    public static final int MAX_DEST_SIZE = 127;



    public static byte[] createForwardPayload(Params params, byte[][] secrets, byte[] destination, byte[] message) throws Exception, IOException {
        if (!(destination.length > 0 && destination.length < MAX_DEST_SIZE)) {
            throw new Exception("Destination has to be between 1 and " +
                    MAX_DEST_SIZE + " bytes long");
        }

        int nu = secrets.length;

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(2);
            packer.packBinaryHeader(destination.length);
            packer.writePayload(destination);
            packer.packBinaryHeader(message.length);
            packer.writePayload(message);
            packer.close();
        } catch (IOException ex) {
            throw new Exception("Failed to pack destination and message");
        }

        byte[] encodedDestAndMsg = packer.toByteArray();

        int msgTotalSize = params.bodyLength() - params.keyLength();
        byte[] initialPad = {(byte) 0x7f};
        int padLen = msgTotalSize - (encodedDestAndMsg.length + 1);

        if (padLen < 0) {
            throw new Exception("Insufficient space for message");
        }

        byte[] padBytes = new byte[padLen];
        Arrays.fill(padBytes, (byte) 0xff);

        byte[] payload = concatenate(encodedDestAndMsg, initialPad, padBytes);

        byte[] mac = params.mu(params.hpi(secrets[nu - 1]), payload);
        byte[] body = concatenate(mac, payload);

        byte[] delta = params.pi(params.hpi(secrets[nu - 1]), body);

        for (int i = nu - 2; i >= 0; i--) {
            delta = params.pi(params.hpi(secrets[i]), delta);
        }

        return delta;
    }
}