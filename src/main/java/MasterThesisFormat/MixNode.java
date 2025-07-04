package MasterThesisFormat;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.MixFormats.Packet;
import MasterThesisFormat.VM.VM;
import MasterThesisFormat.header.InstructionHeader;
import javasphinx.packet.SphinxPacket;
import org.bouncycastle.math.ec.ECPoint;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.math.BigInteger;
import java.util.Arrays;

public class MixNode {
    private final BigInteger secret;
    private final Params params;
    private final VM vm;

    public MixNode(BigInteger secret, Params params) {
        this.secret = secret;
        this.params = params;
        this.vm = new VM(secret, params);
    }

    /**
     *
     * The expected layout matches [alpha | encrypted instructions | MAC | packet]:
     */
    public Packet process(byte[] rawPacket) {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(rawPacket);
        byte[] encodedAlpha, encInstr, mac, packetRaw;
        try {
            int arrLen = unpacker.unpackArrayHeader();
            if (arrLen != 4) {
                throw new IllegalArgumentException("Invalid instruction packet layout");
            }
            encodedAlpha = unpacker.readPayload(unpacker.unpackBinaryHeader());
            encInstr = unpacker.readPayload(unpacker.unpackBinaryHeader());
            mac = unpacker.readPayload(unpacker.unpackBinaryHeader());
            packetRaw = unpacker.readPayload(unpacker.unpackBinaryHeader());
            unpacker.close();
        } catch (java.io.IOException e) {
            throw new RuntimeException("Failed to unpack instruction packet", e);
        }

        ECPoint headerAlpha = SerializationUtils.decodeECPoint(encodedAlpha);

        ECPoint shared  = params.getGroup().expon(headerAlpha, secret);

        byte[] aesKey = params.getAesKey(shared);

        byte[] plainInstr;
        try {
            plainInstr = params.xorRho(params.hrho(aesKey), encInstr);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt instructions", e);
        }

        byte[] expectedMac = params.mu(params.hmu(aesKey), plainInstr);
        if (!Arrays.equals(expectedMac, mac)) {
            throw new RuntimeException("Instruction MAC mismatch");
        }

        try {
            vm.interpret(packetRaw, plainInstr);
        } catch (Exception e) {
            throw new RuntimeException("VM execution failed", e);
        }

        //TODO weiter machen!
        return null;
    }
}
