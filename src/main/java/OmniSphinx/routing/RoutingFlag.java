package OmniSphinx.routing;

public enum RoutingFlag {
    RELAY("relay");

    private final String value;

    RoutingFlag(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}