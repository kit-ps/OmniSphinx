package microBenchmarks;

import OmniSphinx.Client;
import OmniSphinx.ClientUtil;
import OmniSphinx.InstructionPacket.InstructionPacket;
import OmniSphinx.Params;
import OmniSphinx.pki.PkiEntry;
import OmniSphinx.pki.PkiGenerator;
import OmniSphinx.routing.RandomRoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Before;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

public class SphinxPackageCreationBenchmark {
    private static final int RUNS = 100;

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
            InstructionPacket packet = client.createSphinxInstructionPacket(nodeList, keys, destination, message);
            long duration = System.nanoTime() - start;
            packet.getPayload();
            double durationMs = duration / 1_000_000.0;
            if(i == 0) {
                continue;
            }
            creationStats.record(durationMs);
        }

        System.out.printf("Sphinx creation avg ms: %.2f (min=%.2f, max=%.2f)%n",
                creationStats.getAverage(), creationStats.getMin(), creationStats.getMax());

        assertTrue(creationStats.getCount() > 0);
    }
}