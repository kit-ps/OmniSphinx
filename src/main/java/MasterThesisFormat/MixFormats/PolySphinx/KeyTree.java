package MasterThesisFormat.MixFormats.PolySphinx;

import MasterThesisFormat.Params;

public class KeyTree {

    private final Params params;
    private final byte[] seed;


    public KeyTree(Params params, byte[] seed) {
        this.params = params;
        this.seed = seed.clone();
    }


    public byte[] root() {
        return params.hash(seed);
    }


    public byte[] derive(byte[] path) {
        byte[] current = root();

        for (byte p : path) {
            for (int i = 0; i <= (p & 0xFF); i++) {
                increment(current);
            }
            current = params.hash(current);
        }

        return current;
    }


    private static void increment(byte[] x) {
        for (int i = x.length - 1; i >= 0; i--) {
            x[i]++;
            if (x[i] != 0) {
                break;
            }
        }
    }
}