package MasterThesisFormat.MixFormats.Sphinx;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.Params;
import MasterThesisFormat.crypto.ECCGroup;
import MasterThesisFormat.header.InstructionEncryptor;
import MasterThesisFormat.header.InstructionHeader;
import org.bouncycastle.math.ec.ECPoint;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;

import java.io.IOException;
import java.util.Arrays;

import static MasterThesisFormat.SerializationUtils.concatenate;

public final class SphinxUtil {



    public static InstructionPacket createSphinxInstructionPacket(Params params, byte[][] nodelist, ECPoint[] keys, byte[] destination, byte[] message) throws Exception {

        int hops = nodelist.length;
        if (keys.length != hops) {
            throw new IllegalArgumentException("nodelist/keys length mismatch");
        }

        ECCGroup group = params.getGroup();

        java.math.BigInteger x = group.genSecret();
        ECPoint[] alphas = new ECPoint[hops];
        ECPoint[] sharedSecrets = new ECPoint[hops];
        byte[][] secrets = new byte[hops][];
        for (int i = 0; i < hops; i++) {
            alphas[i] = group.expon(group.getGenerator(), x);
            sharedSecrets[i] = group.expon(keys[i], x);
            secrets[i] = params.getAesKey(sharedSecrets[i]);
            java.math.BigInteger b = params.hb(alphas[i], secrets[i]);
            x = x.multiply(b).mod(group.getOrder());
        }

        //create Payload
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

        byte[] mac = params.mac(params.hpi(secrets[hops - 1]), payload);

        byte[] body = concatenate(mac, payload);

        byte[] delta = params.encrypt(params.hpi(secrets[hops - 1]), body);
        for (int i = hops - 2; i >= 0; i--) {
            delta = params.encrypt(params.hpi(secrets[i]), delta);
        }

        //create instruction header
        byte[][] instructions = new byte[hops][];
        for (int i = 0; i < hops; i++) {
            byte salt = params.HPI_SALT;
            instructions[i] = SphinxInstructionPresets.createInstructions(nodelist[i], salt);
        }

        int instructionLen = 0;
        for(byte[] instruction: instructions) {
            instructionLen += instruction.length;
        }

        int instPadLen = params.getInstructionTotalSize() - instructionLen;
        byte[] padding = InstructionEncryptor.padInstructions(params, instPadLen, instructionLen, secrets[0], 0);

        byte[] onion = InstructionEncryptor.encryptWithPadding(params, instructions, secrets, params.getInstructionTotalSize(), padding);

        byte[] finalMac = params.mac(params.hmu(secrets[0]), onion);

        InstructionHeader header = new InstructionHeader(alphas[0], onion, finalMac);

        return new InstructionPacket(header, delta);
    }
}