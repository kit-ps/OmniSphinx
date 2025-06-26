package javasphinx.routing;

public interface RoutingStrategy {

    /**
     * Select a subset of mix node identifiers according to the Client's {@link RoutingStrategy}.
     * identifiers.length MUST be greater than or equal to mixCount.
     * @param identifiers list of mix node ids
     * @param mixCount count of ids to select from identifiers
     * @return mix identifiers
     */
    int[] route(int[] identifiers, int mixCount);
}
