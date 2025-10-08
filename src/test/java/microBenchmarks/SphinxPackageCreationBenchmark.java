package microBenchmarks;

import MasterThesisFormat.Client;
import MasterThesisFormat.ClientUtil;
import MasterThesisFormat.Params;
import MasterThesisFormat.pki.PkiEntry;
import MasterThesisFormat.pki.PkiGenerator;
import MasterThesisFormat.routing.RandomRoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

public class SphinxPackageCreationBenchmark {
    private static final int RUNS = 50;

    private Params params;
    private Client client;
    private PkiGenerator generator;
    private byte[][] nodeList;
    private ECPoint[] keys;
    private byte[] destination;
    private final SecureRandom random = new SecureRandom();

    @Before
    public void setUp() throws Exception {
        params = new Params();
        client = new Client(params, new RandomRoutingStrategy());
        generator = new PkiGenerator(params);

        PkiEntry n1 = generator.generateKeyPair();
        PkiEntry n2 = generator.generateKeyPair();
        PkiEntry n3 = generator.generateKeyPair();
        nodeList = new byte[][]{
                ClientUtil.encodeNode(1, 0),
                ClientUtil.encodeNode(2, 0),
                ClientUtil.encodeNode(3, 0)
        };
        keys = new ECPoint[]{n1.pub(), n2.pub(), n3.pub()};
        destination = ClientUtil.encodeNode(1000, 0);
    }

    @Test
    public void benchmarkSphinxPackageCreation() throws Exception {
        BenchmarkStats creationStats = new BenchmarkStats();

        for (int i = 0; i < RUNS; i++) {
            byte[] message = new byte[32 + random.nextInt(32)];
            random.nextBytes(message);

            long start = System.nanoTime();
            var packet = client.createSphinxInstructionPacket(nodeList, keys, destination, message);
            client.packInstructionPacket(packet);
            long duration = System.nanoTime() - start;
            creationStats.record(duration);
        }

        System.out.printf("Sphinx creation avg ns: %d (min=%d, max=%d)%n",
                creationStats.getAverage(), creationStats.getMin(), creationStats.getMax());

        assertTrue(creationStats.getCount() > 0);
    }
}