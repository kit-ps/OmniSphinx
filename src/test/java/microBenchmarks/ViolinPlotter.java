package microBenchmarks;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Path2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.imageio.ImageIO;

public final class ViolinPlotter {
    private static final int WIDTH = 900;
    private static final int HEIGHT = 600;
    private static final int MARGIN = 80;

    private ViolinPlotter() {
    }

    public static void plot(String title, Map<String, BenchmarkStats> statsByLabel, Path outputFile) throws IOException {
        BufferedImage image = new BufferedImage(WIDTH, HEIGHT, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, WIDTH, HEIGHT);

        List<String> labels = new ArrayList<>(statsByLabel.keySet());
        List<double[]> densityValues = new ArrayList<>();
        List<double[]> densityYs = new ArrayList<>();

        double globalMin = Double.MAX_VALUE;
        double globalMax = -Double.MAX_VALUE;
        double maxDensity = 0.0;

        for (String label : labels) {
            BenchmarkStats stats = statsByLabel.get(label);
            if (stats.getValues().isEmpty()) {
                densityValues.add(new double[0]);
                densityYs.add(new double[0]);
                continue;
            }
            List<Double> values = stats.getValues();
            double localMin = values.stream().mapToDouble(Double::doubleValue).min().orElse(0);
            double localMax = values.stream().mapToDouble(Double::doubleValue).max().orElse(0);
            globalMin = Math.min(globalMin, localMin);
            globalMax = Math.max(globalMax, localMax);

            double bandwidth = computeBandwidth(values);
            int steps = 200;
            double[] yPoints = new double[steps];
            double[] densities = new double[steps];
            double range = localMax - localMin == 0 ? 1 : localMax - localMin;
            for (int i = 0; i < steps; i++) {
                double y = localMin + (range * i) / (steps - 1);
                double density = kernelDensity(values, bandwidth, y);
                yPoints[i] = y;
                densities[i] = density;
                maxDensity = Math.max(maxDensity, density);
            }
            densityYs.add(yPoints);
            densityValues.add(densities);
        }

        if (globalMin == Double.MAX_VALUE || globalMax == -Double.MAX_VALUE) {
            ImageIO.write(image, "png", outputFile.toFile());
            g.dispose();
            return;
        }

        if (globalMax == globalMin) {
            globalMax = globalMin + 1;
        }

        double plotHeight = HEIGHT - 2.0 * MARGIN;
        double plotWidth = WIDTH - 2.0 * MARGIN;
        double xStep = plotWidth / (labels.size() + 1);
        double maxHalfWidth = xStep * 0.35;

        g.setColor(Color.GRAY);
        g.setStroke(new BasicStroke(1.2f));
        g.drawLine(MARGIN, HEIGHT - MARGIN, WIDTH - MARGIN, HEIGHT - MARGIN);
        g.drawLine(MARGIN, HEIGHT - MARGIN, MARGIN, MARGIN / 2);

        g.setFont(new Font("SansSerif", Font.BOLD, 16));
        g.drawString(title, MARGIN, MARGIN / 2 - 10);

        g.setFont(new Font("SansSerif", Font.PLAIN, 12));
        g.drawString("ns", MARGIN - 35, MARGIN - 10);

        int tickCount = 5;
        for (int i = 0; i <= tickCount; i++) {
            double value = globalMin + (globalMax - globalMin) * i / tickCount;
            int y = (int) (HEIGHT - MARGIN - (value - globalMin) / (globalMax - globalMin) * plotHeight);
            g.drawLine(MARGIN - 5, y, MARGIN + 5, y);
            g.drawString(String.format("%.0f", value), MARGIN - 70, y + 5);
        }

        g.setColor(new Color(70, 130, 180, 160));
        for (int i = 0; i < labels.size(); i++) {
            double centerX = MARGIN + (i + 1) * xStep;
            double[] yPoints = densityYs.get(i);
            double[] densities = densityValues.get(i);
            if (yPoints.length == 0 || maxDensity == 0) {
                continue;
            }

            Path2D shape = new Path2D.Double();
            for (int j = 0; j < yPoints.length; j++) {
                double yValue = yPoints[j];
                double normDensity = densities[j] / maxDensity;
                double halfWidth = normDensity * maxHalfWidth;
                double yPixel = HEIGHT - MARGIN - (yValue - globalMin) / (globalMax - globalMin) * plotHeight;
                if (j == 0) {
                    shape.moveTo(centerX - halfWidth, yPixel);
                } else {
                    shape.lineTo(centerX - halfWidth, yPixel);
                }
            }
            for (int j = yPoints.length - 1; j >= 0; j--) {
                double yValue = yPoints[j];
                double normDensity = densities[j] / maxDensity;
                double halfWidth = normDensity * maxHalfWidth;
                double yPixel = HEIGHT - MARGIN - (yValue - globalMin) / (globalMax - globalMin) * plotHeight;
                shape.lineTo(centerX + halfWidth, yPixel);
            }
            shape.closePath();
            g.fill(shape);

            g.setColor(Color.DARK_GRAY);
            g.setFont(new Font("SansSerif", Font.PLAIN, 11));
            int labelWidth = g.getFontMetrics().stringWidth(labels.get(i));
            g.drawString(labels.get(i), (int) (centerX - labelWidth / 2.0), HEIGHT - MARGIN + 20);
            g.setColor(new Color(70, 130, 180, 160));
        }

        ImageIO.write(image, "png", outputFile.toFile());
        g.dispose();
    }

    private static double computeBandwidth(List<Double> values) {
        double mean = values.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        double variance = values.stream().mapToDouble(v -> Math.pow(v - mean, 2)).average().orElse(1.0);
        double std = Math.sqrt(variance);
        double n = values.size();
        double bandwidth = 1.06 * std * Math.pow(n, -0.2);
        if (bandwidth == 0) {
            bandwidth = std == 0 ? 1 : std * 0.1;
        }
        return bandwidth;
    }

    private static double kernelDensity(List<Double> values, double bandwidth, double x) {
        double denom = values.size() * bandwidth * Math.sqrt(2 * Math.PI);
        double sum = 0;
        for (double value : values) {
            double z = (x - value) / bandwidth;
            sum += Math.exp(-0.5 * z * z);
        }
        return denom == 0 ? 0 : sum / denom;
    }
}