package OmniSphinx.routing;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;

public class RandomRoutingStrategy implements RoutingStrategy {
    @Override
    public int[] route(final int[] identifiers, final int mixCount) {

        SecureRandom secureRandom = new SecureRandom();

        long[] randoms = new long[identifiers.length];
        for (int i = 0; i < randoms.length; i++) {
            byte[] rand = new byte[8];
            secureRandom.nextBytes(rand);
            randoms[i] = (new BigInteger(1, rand)).longValue();
        }

        HashMap<Long, Integer> randToIndex = new HashMap<>();
        for (int i = 0; i < randoms.length; i++) {
            randToIndex.put(randoms[i], i);
        }

        Arrays.sort(randoms);

        int[] result = new int[mixCount];
        for (int i = 0; i < mixCount; i++) {
            result[i] = identifiers[randToIndex.get(randoms[i])];
        }

        return result;
    }
}
