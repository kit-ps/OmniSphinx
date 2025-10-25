package MasterThesisFormat.MixFormats.Sphinx;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.OmniSphinxException;
import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import MasterThesisFormat.crypto.ECCGroup;
import MasterThesisFormat.header.InstructionEncryptor;
import MasterThesisFormat.header.InstructionHeader;
import org.bouncycastle.math.ec.ECPoint;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import static MasterThesisFormat.SerializationUtils.concatenate;

public final class SphinxUtil {



    public static InstructionPacket createSphinxInstructionPacket(Params params, byte[][] nodelist, ECPoint[] keys, byte[] destination, byte[] message) throws Exception {

        int hops = nodelist.length;
        System.out.println("[SphinxUtil] Creating instruction packet with " + hops + " hops");
        if (keys.length != hops) {
            throw new IllegalArgumentException("nodelist/keys length mismatch");
        }

        ECCGroup group = params.getGroup();

        java.math.BigInteger x = group.genSecret();
        System.out.println("[SphinxUtil] Initial secret exponent x=" + toHex(x.toByteArray()));
        ECPoint[] alphas = new ECPoint[hops];
        ECPoint[] sharedSecrets = new ECPoint[hops];
        byte[][] secrets = new byte[hops][];
        for (int i = 0; i < hops; i++) {
            alphas[i] = group.expon(group.getGenerator(), x);
            System.out.println("[SphinxUtil] Hop " + i + " alpha (compressed): " + toHex(alphas[i].getEncoded(true)));
            sharedSecrets[i] = group.expon(keys[i], x);
            System.out.println("[SphinxUtil] Hop " + i + " shared secret (compressed): " + toHex(sharedSecrets[i].getEncoded(true)));
            secrets[i] = params.getAesKey(sharedSecrets[i]);
            System.out.println("[SphinxUtil] Hop " + i + " AES key: " + toHex(secrets[i]));
            java.math.BigInteger b = params.hb(alphas[i], secrets[i]);
            System.out.println("[SphinxUtil] Hop " + i + " blinding factor b=" + toHex(b.toByteArray()));
            x = x.multiply(b).mod(group.getOrder());
            System.out.println("[SphinxUtil] Hop " + i + " updated secret exponent x=" + toHex(x.toByteArray()));
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
        System.out.println("[SphinxUtil] Destination bytes (len=" + destination.length + "): " + toHex(destination));
        //System.out.println("[SphinxUtil] Message bytes (len=" + message.length + "): " + toHex(message));
        //System.out.println("[SphinxUtil] Encoded destination+message length=" + encodedDestAndMsg.length + ", bytes=" + toHex(encodedDestAndMsg));

        int msgTotalSize = params.bodyLength() - params.keyLength();
        byte[] initialPad = {(byte) 0x7f};
        int padLen = msgTotalSize - (encodedDestAndMsg.length + 1);

        if (padLen < 0) {
            throw new Exception("Insufficient space for message");
        }

        byte[] padBytes = new byte[padLen];
        Arrays.fill(padBytes, (byte) 0xff);
        System.out.println("[SphinxUtil] Payload pad length=" + padLen);

        byte[] payload = concatenate(encodedDestAndMsg, initialPad, padBytes);
        //System.out.println("[SphinxUtil] Payload length=" + payload.length + ", bytes=" + toHex(payload));

        byte[] mac = params.mac(params.hpi(secrets[hops - 1]), payload);
        System.out.println("[SphinxUtil] Payload MAC: " + toHex(mac));

        byte[] body = concatenate(mac, payload);
        //System.out.println("[SphinxUtil] Body length=" + body.length + ", bytes=" + toHex(body));

        byte[] delta = params.encrypt(params.hpi(secrets[hops - 1]), body);
        //System.out.println("[SphinxUtil] Initial encrypted body (delta) length=" + delta.length + ", bytes=" + toHex(delta));
        for (int i = hops - 2; i >= 0; i--) {
            delta = params.encrypt(params.hpi(secrets[i]), delta);
            //System.out.println("[SphinxUtil] Delta after hop " + i + " encryption length=" + delta.length + ", bytes=" + toHex(delta));
        }

        //create instruction header
        byte[][] instructions = new byte[hops][];
        for (int i = 0; i < hops; i++) {
            byte salt = Params.HPI_SALT;
            instructions[i] = SphinxInstructionPresets.createInstructions(nodelist[i], salt);
        }

        int headerLen = 0;
        for(byte[] instruction: instructions) {
            headerLen += instruction.length + params.keyLength();
        }
        System.out.println("[SphinxUtil] Total beta length=" + headerLen);

        int instPadLen = params.getInstructionTotalSize() - headerLen + params.keyLength(); //nochmal params.keyLength abziehen, weil die letzte Instruktion kein Gamma hat!

        if(instPadLen < 0) {
            throw new OmniSphinxException("Header to small!");
        }
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomPad = new byte[instPadLen];
        secureRandom.nextBytes(randomPad);

        instructions[hops - 1] = concatenate(instructions[hops - 1], randomPad);
        byte[] onion = InstructionEncryptor.encryptFixedSize(params, instructions, secrets, params.getInstructionTotalSize());

        byte[] finalMac = params.mac(params.hmu(secrets[0]), onion);
        System.out.println("[SphinxUtil] Final instruction MAC: " + toHex(finalMac));

        InstructionHeader header = new InstructionHeader(alphas[0], onion, finalMac);

        byte[] encodedAlpha0 = alphas[0].getEncoded(true);
        System.out.println("[SphinxUtil] Final packet alpha (compressed) length=" + encodedAlpha0.length + ", bytes=" + toHex(encodedAlpha0));
        System.out.println("[SphinxUtil] Final delta length=" + delta.length + ", bytes=" + toHex(delta));

        return new InstructionPacket(header, delta);
    }

    public static String toHex(byte[] data) {
        return Arrays.toString(data);
    }
}