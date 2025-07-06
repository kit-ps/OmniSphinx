package MasterThesisFormat;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.MixFormats.Sphinx.SphinxUtil;
import MasterThesisFormat.VM.VMUtil;
import MasterThesisFormat.header.InstructionHeader;
import MasterThesisFormat.MixFormats.Sphinx.SphinxInstructionPresets;
import MasterThesisFormat.routing.RoutingStrategy;
import javasphinx.SphinxException;
import MasterThesisFormat.crypto.ECCGroup;
import org.bouncycastle.math.ec.ECPoint;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;

import java.io.IOException;
import java.math.BigInteger;

public class Client {
    public static final int MAX_INSTRUCTION_SIZE = 1024;

    private final Params params;
    private final RoutingStrategy routingStrategy;


    public Client(Params params, RoutingStrategy routingStrategy) {
        this.params = params;
        this.routingStrategy = routingStrategy;
    }

    public Params getParams() {
        return params;
    }

    public RoutingStrategy getRoutingStrategy() {
        return routingStrategy;
    }


    /**
     * Create a forward instruction Sphinx packet.
     * @param nodelist List of encoded mix node identifiers used to route the packet.
     * @param keys List of the corresponding public keys of the mix nodes in nodelist.
     * @param destination Final destination.
     * @param message Data payload.
     * @return Header and payload of a Sphinx packet encrypted in a nested manner.
     */
    public InstructionPacket createSphinxInstructionPacket(byte[][] nodelist, ECPoint[] keys, byte[] destination, byte[] message) throws Exception, IOException {
        int nu = nodelist.length;
        ECCGroup group = params.getGroup();

        BigInteger blindFactor = group.genSecret();
        ECPoint[] alphas = new ECPoint[nu];
        ECPoint[] sharedSecrets = new ECPoint[nu];
        byte[][] secrets = new byte[nu][];
        for (int i = 0; i < nu; i++) {
            alphas[i] = group.expon(group.getGenerator(), blindFactor);
            sharedSecrets[i] = group.expon(keys[i], blindFactor);
            secrets[i] = params.getAesKey(sharedSecrets[i]);
            java.math.BigInteger b = params.hb(alphas[i], secrets[i]);
            blindFactor = blindFactor.multiply(b).mod(group.getOrder());
        }

        byte[] delta = SphinxUtil.createForwardPayload(params, secrets, destination, message);

        byte[] onion = new byte[0];
        byte[] sigma;

        for (int i = nodelist.length - 1; i >= 0; i--) {
            byte[] instr = SphinxInstructionPresets.createInstructions(nodelist[i][0]);

            int plainLen = instr.length + onion.length;
            if (plainLen + params.keyLength() > MAX_INSTRUCTION_SIZE) {
                throw new SphinxException("Instructions exceed maximum size");
            }

            byte[] plain = new byte[plainLen];
            System.arraycopy(instr, 0, plain, 0, instr.length);
            System.arraycopy(onion, 0, plain, instr.length, onion.length);

            byte[] enc = params.xorRho(params.hrho(secrets[i]), plain);
            sigma = params.mu(params.hmu(secrets[i]), plain);

            onion = new byte[sigma.length + enc.length];
            System.arraycopy(sigma, 0, onion, 0, sigma.length);
            System.arraycopy(enc, 0, onion, sigma.length, enc.length);
        }

        byte[] finalSigma = VMUtil.slice(onion, 0, params.keyLength());
        byte[] finalOnion = VMUtil.slice(onion, params.keyLength(), onion.length);

        InstructionHeader header = new InstructionHeader(alphas[0], finalOnion, finalSigma);

        return new InstructionPacket(header, delta);
    }

    /**
     *
     * Layout:
     * [alpha | encrypted instructions | MAC | payload]
     *
     */
    public byte[] packInstructionPacket(InstructionPacket packet) throws Exception {
        InstructionHeader header = packet.getHeader();

        byte[] encodedAlpha = SerializationUtils.encodeECPoint(header.getAlpha());
        byte[] instructions = header.getInstructions();
        byte[] mac = header.getMAC();

        byte[] payload = packet.getPayload();

        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        try {
            packer.packArrayHeader(4);
            packer.packBinaryHeader(encodedAlpha.length);
            packer.writePayload(encodedAlpha);
            packer.packBinaryHeader(instructions.length);
            packer.writePayload(instructions);
            packer.packBinaryHeader(mac.length);
            packer.writePayload(mac);
            packer.packBinaryHeader(payload.length);
            packer.writePayload(payload);
            packer.close();
        } catch (IOException ex) {
            throw new Exception("Failed to pack instruction packet");
        }

        return packer.toByteArray();
    }
}

