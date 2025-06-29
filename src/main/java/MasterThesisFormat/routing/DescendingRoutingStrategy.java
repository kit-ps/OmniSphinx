package MasterThesisFormat.routing;

import java.util.Arrays;

public class DescendingRoutingStrategy implements RoutingStrategy {
    @Override
    public int[] route(final int[] identifiers, final int mixCount) {
        return Arrays.stream(identifiers)
                .map(i -> -i)
                .sorted()
                .map(i -> -i)
                .limit(mixCount)
                .toArray();
    }
}
