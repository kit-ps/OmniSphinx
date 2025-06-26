package javasphinx.packet;

import java.util.Arrays;

public enum RoutingFlag {
    DESTINATION(String.valueOf((char) 0xf0)),
    RELAY(String.valueOf((char) 0xf1)),
    SURB(String.valueOf((char) 0xf2));

    public static RoutingFlag byValue(String value) {
        return Arrays.stream(RoutingFlag.values())
                .filter(flag -> flag.value().equals(value))
                .findFirst().orElse(null);
    }

    private final String value;

    RoutingFlag(final String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
