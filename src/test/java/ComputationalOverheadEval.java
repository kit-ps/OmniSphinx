import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.InstructionPacket.InstructionPacketAndNextHop;
import MasterThesisFormat.MixFormats.PolySphinx.PolySphinxUtil;
import MasterThesisFormat.MixFormats.PolySphinx.SubHeader;
import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import MasterThesisFormat.VM.VM;
import MasterThesisFormat.VM.VMContext;
import MasterThesisFormat.VM.VMOutput;
import MasterThesisFormat.instruction.InstructionRegister;
import MasterThesisFormat.pki.PkiEntry;
import MasterThesisFormat.pki.PkiGenerator;
import MasterThesisFormat.routing.RandomRoutingStrategy;
import MasterThesisFormat.header.InstructionHeader;
import kotlin.Pair;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;
import org.msgpack.core.MessageUnpacker;
import org.msgpack.core.MessagePack;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

import static org.junit.Assert.assertTrue;

public class ComputationalOverheadEval {

    private Params params;
    private Client client;
    private PkiGenerator generator;

    private byte[][] nodeList;
    private ECPoint[] keys;
    private BigInteger[] privs;
    private byte[] destination;

    private PkiEntry replication;
    private PkiEntry relay;
    private PkiEntry exit;
    private PkiEntry receiver;
    private byte[] replicationNode;
    private byte[] relayNode;
    private byte[] exitNode;
    private byte[] receiverId;
    private List<byte[][]> suffixPaths;
    private List<ECPoint[]> keySets;
    private byte[] seed;
    private byte[] msg;

    @Before
    public void setUp() throws Exception {
        params = new Params();
        client = new Client(params, new RandomRoutingStrategy());
        generator = new PkiGenerator(params);

        // Sphinx setup
        PkiEntry n1 = generator.generateKeyPair();
        PkiEntry n2 = generator.generateKeyPair();
        PkiEntry n3 = generator.generateKeyPair();
        nodeList = new byte[][]{
                ClientUtil.encodeNode(1, 0),
                ClientUtil.encodeNode(2, 0),
                ClientUtil.encodeNode(3, 0)
        };
        keys = new ECPoint[]{n1.pub(), n2.pub(), n3.pub()};
        privs = new BigInteger[]{n1.priv(), n2.priv(), n3.priv()};
        destination = ClientUtil.encodeNode(1000, 0);

        // PolySphinx setup
        replication = generator.generateKeyPair();
        relay = generator.generateKeyPair();
        exit = generator.generateKeyPair();
        receiver = generator.generateKeyPair();
        replicationNode = ClientUtil.encodeNode(10, 0);
        relayNode = ClientUtil.encodeNode(11, 0);
        exitNode = ClientUtil.encodeNode(12, 0);
        receiverId = ClientUtil.encodeNode(1001, 0);
        suffixPaths = new ArrayList<>();
        suffixPaths.add(new byte[][]{relayNode, exitNode, receiverId});
        keySets = new ArrayList<>();
        keySets.add(new ECPoint[]{relay.pub(), exit.pub(), receiver.pub()});
        seed = new byte[16];
        new SecureRandom().nextBytes(seed);
        msg = "hi".getBytes();
    }

    @Test
    public void measureSphinxOverhead() throws Exception {
        int runs = 100;
        long creationTotal = 0;
        long preTotal = 0;
        long vmTotal = 0;
        long fwdTotal = 0;

        for (int r = 0; r < runs; r++) {
            long createStart = System.nanoTime();
            InstructionPacket packet = client.createSphinxInstructionPacket(nodeList, keys, destination, msg);
            byte[] raw = client.packInstructionPacket(packet);
            long createEnd = System.nanoTime();
            creationTotal += createEnd - createStart;

            long preRun = 0;
            long vmRun = 0;
            long fwdRun = 0;

            byte[] current = raw;
            for (int i = 0; i < privs.length; i++) {
                ProcessResult res = measureProcessing(current, privs[i]);
                preRun += res.preprocessing;
                vmRun += res.vm;
                fwdRun += res.forwarding;
                if (i < privs.length - 1) {
                    InstructionPacket nextPacket = res.packets.get(0).getPacket();
                    current = client.packInstructionPacket(nextPacket);
                }
            }

            preTotal += preRun;
            vmTotal += vmRun;
            fwdTotal += fwdRun;
        }

        System.out.printf("Sphinx creation ns avg: %d\n", creationTotal / runs);
        System.out.printf("Sphinx preprocessing ns avg: %d\n", preTotal / runs);
        System.out.printf("Sphinx VM ns avg: %d\n", vmTotal / runs);
        System.out.printf("Sphinx forwarding ns avg: %d\n", fwdTotal / runs);
        assertTrue(creationTotal >= 0);
    }

    @Test
    public void measurePolySphinxOverhead() throws Exception {
        int runs = 100;
        long creationTotal = 0;
        long replicationPreTotal = 0;
        long replicationVmTotal = 0;
        long replicationFwdTotal = 0;
        long relayPreTotal = 0;
        long relayVmTotal = 0;
        long relayFwdTotal = 0;
        long exitPreTotal = 0;
        long exitVmTotal = 0;
        long exitFwdTotal = 0;

        for (int r = 0; r < runs; r++) {
            long createStart = System.nanoTime();
            Pair<InstructionPacket, List<SubHeader>> pair = PolySphinxUtil.createPolySphinxPacketForTests(
                    params, replicationNode, replication.pub(), suffixPaths, msg, seed, keySets);
            InstructionPacket packet = pair.component1();
            byte[] raw = client.packInstructionPacket(packet);
            long createEnd = System.nanoTime();
            creationTotal += createEnd - createStart;

            ProcessResult replicationRes = measureProcessing(raw, replication.priv());
            InstructionPacketAndNextHop relayPacketAndHop = replicationRes.packets.get(0);
            byte[] relayRaw = client.packInstructionPacket(relayPacketAndHop.getPacket());

            ProcessResult relayRes = measureProcessing(relayRaw, relay.priv());
            InstructionPacketAndNextHop exitPacketAndHop = relayRes.packets.get(0);
            byte[] exitRaw = client.packInstructionPacket(exitPacketAndHop.getPacket());

            ProcessResult exitRes = measureProcessing(exitRaw, exit.priv());

            replicationPreTotal += replicationRes.preprocessing;
            replicationVmTotal += replicationRes.vm;
            replicationFwdTotal += replicationRes.forwarding;
            relayPreTotal += relayRes.preprocessing;
            relayVmTotal += relayRes.vm;
            relayFwdTotal += relayRes.forwarding;
            exitPreTotal += exitRes.preprocessing;
            exitVmTotal += exitRes.vm;
            exitFwdTotal += exitRes.forwarding;
        }

        System.out.printf("PolySphinx creation ns avg: %d\n", creationTotal / runs);
        System.out.printf("PolySphinx replication preprocessing ns avg: %d\n", replicationPreTotal / runs);
        System.out.printf("PolySphinx replication VM ns avg: %d\n", replicationVmTotal / runs);
        System.out.printf("PolySphinx replication forwarding ns avg: %d\n", replicationFwdTotal / runs);
        System.out.printf("PolySphinx relay preprocessing ns avg: %d\n", relayPreTotal / runs);
        System.out.printf("PolySphinx relay VM ns avg: %d\n", relayVmTotal / runs);
        System.out.printf("PolySphinx relay forwarding ns avg: %d\n", relayFwdTotal / runs);
        System.out.printf("PolySphinx exit preprocessing ns avg: %d\n", exitPreTotal / runs);
        System.out.printf("PolySphinx exit VM ns avg: %d\n", exitVmTotal / runs);
        System.out.printf("PolySphinx exit forwarding ns avg: %d\n", exitFwdTotal / runs);
        assertTrue(creationTotal >= 0);
    }

    private static class ProcessResult {
        final List<InstructionPacketAndNextHop> packets;
        final long preprocessing;
        final long vm;
        final long forwarding;
        ProcessResult(List<InstructionPacketAndNextHop> packets, long preprocessing, long vm, long forwarding) {
            this.packets = packets;
            this.preprocessing = preprocessing;
            this.vm = vm;
            this.forwarding = forwarding;
        }
    }

    private ProcessResult measureProcessing(byte[] rawPacket, BigInteger privKey) throws Exception {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(rawPacket);
        int arrLen = unpacker.unpackArrayHeader();
        if (arrLen != 4) {
            throw new IllegalArgumentException("Invalid instruction packet layout");
        }
        byte[] encodedAlpha = unpacker.readPayload(unpacker.unpackBinaryHeader());
        byte[] encInstr = unpacker.readPayload(unpacker.unpackBinaryHeader());
        byte[] mac = unpacker.readPayload(unpacker.unpackBinaryHeader());
        byte[] packetRaw = unpacker.readPayload(unpacker.unpackBinaryHeader());
        unpacker.close();

        long preStart = System.nanoTime();
        ECPoint alpha = SerializationUtils.decodeECPoint(encodedAlpha);
        ECPoint sharedSecret = params.getGroup().expon(alpha, privKey);
        byte[] aesKey = params.getAesKey(sharedSecret);
        byte[] plainInstr = params.xorRho(params.hrho(aesKey), encInstr);
        byte[] expectedMac = params.mu(params.hmu(aesKey), plainInstr);
        if (!Arrays.equals(expectedMac, mac)) {
            throw new RuntimeException("Instruction MAC mismatch");
        }
        BigInteger b = params.hb(alpha, aesKey);
        alpha = params.getGroup().expon(alpha, b);
        long preEnd = System.nanoTime();

        Map<Byte, byte[]> register = new HashMap<>();
        register.put(InstructionRegister.NEXT_ALPHA.getCode(), alpha.getEncoded(true));
        register.put(InstructionRegister.INSTRUCTIONS.getCode(), plainInstr);
        register.put(InstructionRegister.MAC.getCode(), mac);
        register.put(InstructionRegister.PAYLOAD.getCode(), packetRaw);
        VMContext context = new VMContext(register);
        VM vm = new VM(privKey, params);
        long vmStart = System.nanoTime();
        List<VMOutput> outputs = vm.interpret(context);
        long vmEnd = System.nanoTime();

        long fwdStart = vmEnd;
        List<InstructionPacketAndNextHop> packets = new ArrayList<>();
        for (VMOutput out : outputs) {
            ECPoint nextAlpha = SerializationUtils.decodeECPoint(out.getNextAlpha());
            InstructionHeader header = new InstructionHeader(nextAlpha, out.getInstructions(), out.getMAC());
            InstructionPacket packet = new InstructionPacket(header, out.getOutgoingPayload());
            packets.add(new InstructionPacketAndNextHop(out.getNextHop(), packet));
        }
        long fwdEnd = System.nanoTime();

        return new ProcessResult(packets, preEnd - preStart, vmEnd - vmStart, fwdEnd - fwdStart);
    }
}