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

        byte[] encodedMessage;
        try (MessageBufferPacker packer = MessagePack.newDefaultBufferPacker()) {
            packer.packArrayHeader(1);
            packer.packBinaryHeader(message.length);
            packer.writePayload(message);
            encodedMessage = packer.toByteArray();
        } catch (IOException e) {
            throw new Exception("Failed to encode destination payload", e);
        }

        int msgTotalSize = params.bodyLength() - params.keyLength();
        byte[] initialPad = {(byte) 0x7f};
        int padLen = msgTotalSize - (encodedMessage.length + 1);

        if (padLen < 0) {
            throw new Exception("Insufficient space for message");
        }

        byte[] padBytes = new byte[padLen];
        Arrays.fill(padBytes, (byte) 0xff);

        byte[] payload = concatenate(encodedMessage, initialPad, padBytes);

        byte[] mac = params.mac(params.hpi(secrets[hops - 1]), payload);

        byte[] body = concatenate(mac, payload);

        byte[] delta = params.encrypt(params.hpi(secrets[hops - 1]), body);
        for (int i = hops - 2; i >= 0; i--) {
            delta = params.encrypt(params.hpi(secrets[i]), delta);
        }

        //create instruction header
        byte[][] instructions = new byte[hops][];
        for (int i = 0; i < hops; i++) {
            byte salt = Params.HPI_SALT;
            if (i == hops - 1) {
                instructions[i] = SphinxInstructionPresets.createExitInstructions(destination, salt);
            } else {
                instructions[i] = SphinxInstructionPresets.createInstructions(nodelist[i+1], salt);
            }
        }

        int headerLen = 0;
        for(byte[] instruction: instructions) {
            headerLen += instruction.length + params.keyLength();
        }

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

        InstructionHeader header = new InstructionHeader(alphas[0], onion, finalMac);

        return new InstructionPacket(header, delta);
    }
}