package microBenchmarks;

import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.MixFormats.PolySphinx.PolySphinxUtil;
import MasterThesisFormat.MixFormats.PolySphinx.SubHeader;
import MasterThesisFormat.Params;
import MasterThesisFormat.pki.PkiEntry;
import MasterThesisFormat.pki.PkiGenerator;
import MasterThesisFormat.routing.RandomRoutingStrategy;
import kotlin.Pair;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class PolySphinxPackageCreationBenchmark {
    private static final int RUNS = 50;

    private Params params;
    private Client client;
    private PkiGenerator generator;
    private byte[] replicationNode;
    private List<byte[][]> suffixPaths;
    private List<ECPoint[]> keySets;
    private List<byte[]> receivers;
    private ECPoint replicationPub;
    private final SecureRandom random = new SecureRandom();

    @Before
    public void setUp() throws Exception {
        params = new Params();
        client = new Client(params, new RandomRoutingStrategy());
        generator = new PkiGenerator(params);

        PkiEntry replication = generator.generateKeyPair();
        PkiEntry relay = generator.generateKeyPair();
        PkiEntry exit = generator.generateKeyPair();
        PkiEntry receiver = generator.generateKeyPair();

        replicationNode = ClientUtil.encodeNode(10, 0);
        byte[] relayNode = ClientUtil.encodeNode(11, 0);
        byte[] exitNode = ClientUtil.encodeNode(12, 0);
        byte[] receiverId = ClientUtil.encodeNode(1001, 0);

        suffixPaths = new ArrayList<>();
        suffixPaths.add(new byte[][]{relayNode, exitNode});

        keySets = new ArrayList<>();
        keySets.add(new ECPoint[]{relay.pub(), exit.pub()});

        receivers = new ArrayList<>();
        receivers.add(Arrays.copyOf(receiverId, params.keyLength()));
        replicationPub = replication.pub();
    }

    @Test
    public void benchmarkPolySphinxPackageCreation() throws Exception {
        BenchmarkStats creationStats = new BenchmarkStats();

        for (int i = 0; i < RUNS; i++) {
            byte[] message = new byte[32 + random.nextInt(32)];
            random.nextBytes(message);

            long start = System.nanoTime();
            byte[] runSeed = new byte[16];
            random.nextBytes(runSeed);
            Pair<InstructionPacket, List<SubHeader>> pair = PolySphinxUtil.createPolySphinxPacketForTests(
                    params, replicationNode, replicationPub, suffixPaths, receivers,message, runSeed, keySets);
            client.packInstructionPacket(pair.component1());
            long duration = System.nanoTime() - start;
            creationStats.record(duration);
        }

        System.out.printf("PolySphinx creation avg ns: %d (min=%d, max=%d)%n",
                creationStats.getAverage(), creationStats.getMin(), creationStats.getMax());

        assertTrue(creationStats.getCount() > 0);
    }
}
