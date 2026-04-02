package OmniSphinx.benchmarks;

import OmniSphinx.Client;
import OmniSphinx.ClientUtil;
import OmniSphinx.InstructionPacket.InstructionPacket;
import OmniSphinx.Params;
import OmniSphinx.crypto.ECCGroup;
import OmniSphinx.pki.PkiEntry;
import OmniSphinx.pki.PkiGenerator;
import OmniSphinx.routing.RandomRoutingStrategy;
import org.bouncycastle.math.ec.ECPoint;

import java.nio.file.Path;
import java.security.SecureRandom;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@BenchmarkMode(Mode.SampleTime)
@State(Scope.Benchmark)
public class SphinxPackageCreationBenchmark {
    private Params params;
    private Client client;
    private PkiGenerator generator;
    private byte[][] nodeList;
    private ECPoint[] keys;
    private byte[] destination;
    private final SecureRandom random = new SecureRandom();
    private byte[] message;

    @Setup
    public void setUp() throws Exception {
        params = new Params(16, 52, 0, new ECCGroup(), 112);
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
        message = new byte[32];
        random.nextBytes(message);
    }

    @Benchmark
    public InstructionPacket sphinxCreation() throws Exception {
        return client.createSphinxInstructionPacket(nodeList, keys, destination, message);
    }

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
            .include("\\b" + SphinxPackageCreationBenchmark.class.getSimpleName())
            .forks(1)
            .resultFormat(ResultFormatType.JSON)
            .result(Path.of("target", "benchmarks", "sphinx-creation.json").toString())
            .build();

        new Runner(opt).run();
    }
}
