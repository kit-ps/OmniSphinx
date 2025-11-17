package microBenchmarks;

public class BenchmarkStats {
    private double total;
    private double min = Double.MAX_VALUE;
    private double max = Double.MIN_VALUE;
    private int count;
    private int errors;
    private Exception lastException;

    public void record(double duration) {
        total += duration;
        count++;
        if (duration < min) {
            min = duration;
        }
        if (duration > max) {
            max = duration;
        }
    }

    public void recordError(Exception e) {
        errors++;
        lastException = e;
    }

    public double getAverage() {
        return count == 0 ? 0 : total / count;
    }

    public double getMin() {
        return count == 0 ? 0 : min;
    }

    public double getMax() {
        return count == 0 ? 0 : max;
    }

    public int getCount() {
        return count;
    }

    public int getErrors() {
        return errors;
    }

    public Exception getLastException() {
        return lastException;
    }
}