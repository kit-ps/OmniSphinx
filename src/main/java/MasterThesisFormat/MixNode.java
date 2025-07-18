package MasterThesisFormat;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.VM.VM;
import MasterThesisFormat.VM.VMContext;
import MasterThesisFormat.VM.VMException;
import MasterThesisFormat.VM.VMOutput;
import MasterThesisFormat.header.InstructionHeader;
import MasterThesisFormat.instruction.InstructionRegister;
import org.bouncycastle.math.ec.ECPoint;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

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
     * layout: [alpha | encrypted instructions | MAC | packet]
     * Layout der encrypted Instructions: [len(instr) | instr | len(nextEncInst) | nextEncInst | len(nextMac) | nextMac]
     */
    public List<InstructionPacket> process(byte[] rawPacket) throws VMException {
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

        //Preprocessing
        ECPoint alpha = SerializationUtils.decodeECPoint(encodedAlpha);

        ECPoint sharedSecret  = params.getGroup().expon(alpha, secret);

        byte[] aesKey = params.getAesKey(sharedSecret);

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

        //compute blinding factors
        BigInteger b = params.hb(alpha, aesKey);

        //Blinding
        alpha = params.getGroup().expon(alpha, b);


        HashMap<Byte, byte[]> register = new HashMap<>();
        register.put(InstructionRegister.NEXT_ALPHA.getCode(), alpha.getEncoded(true));
        register.put(InstructionRegister.INSTRUCTIONS.getCode(), plainInstr);
        register.put(InstructionRegister.MAC.getCode(), mac);
        register.put(InstructionRegister.PAYLOAD.getCode(), packetRaw);
        VMContext vmContext = new VMContext(register);
        List<VMOutput> outputs = vm.interpret(vmContext);

        List<InstructionPacket> packets = new ArrayList<>();
        for (VMOutput out : outputs) {
            ECPoint nextAlpha = SerializationUtils.decodeECPoint(out.getNextAlpha());
            InstructionHeader header = new InstructionHeader(nextAlpha, out.getInstructions(), out.getMAC());
            InstructionPacket packet = new InstructionPacket(header, out.getOutgoingPayload());
            packets.add(packet);
            sendToNextNode(out.getNextHop(), packet);
        }

        return packets;
    }

    private void sendToNextNode(byte[] nextHop, InstructionPacket packet) {
        // Placeholder for network forwarding logic
    }

}
