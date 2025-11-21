package microBenchmarks;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public final class BenchmarkReporter {
    private BenchmarkReporter() {
    }

    public static void printStats(String title, Map<String, BenchmarkStats> statsByLabel) {
        System.out.println("==== " + title + " ====");
        statsByLabel.forEach((label, stats) -> System.out.printf("%s -> avg: %.2f µs (min=%.2f, max=%.2f, runs=%d)%n",
                label, stats.getAverage(), stats.getMin(), stats.getMax(), stats.getCount()));
    }

    public static Path plotViolin(String title, Map<String, BenchmarkStats> statsByLabel, String fileName) throws IOException {
        Path outputDir = Path.of("target", "benchmarks");
        Files.createDirectories(outputDir);
        Path outputFile = outputDir.resolve(fileName);
        ViolinPlotter.plot(title, statsByLabel, outputFile);
        System.out.printf("Violin plot generated at %s%n", outputFile.toAbsolutePath());
        return outputFile;
    }
}