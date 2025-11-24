package OmniSphinx.routing;

import java.util.Arrays;

public class AscendingRoutingStrategy implements RoutingStrategy {
    @Override
    public int[] route(final int[] identifiers, final int mixCount) {
        return Arrays.stream(identifiers).sorted().limit(mixCount).toArray();
    }
}
