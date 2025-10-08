package microBenchmarks;

public class BenchmarkStats {
    private long total;
    private long min = Long.MAX_VALUE;
    private long max = Long.MIN_VALUE;
    private int count;
    private int errors;
    private Exception lastException;

    public void record(long duration) {
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

    public long getAverage() {
        return count == 0 ? 0 : total / count;
    }

    public long getMin() {
        return count == 0 ? 0 : min;
    }

    public long getMax() {
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