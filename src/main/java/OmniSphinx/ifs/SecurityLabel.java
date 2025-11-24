package OmniSphinx.ifs;

public enum SecurityLabel {
    PUBLIC,
    PUBLIC_ALLOWED,
    UNKNOWN,
    SECRET;

    /**
     * Computes the least upper bound of two labels.
     */
    public static SecurityLabel join(SecurityLabel a, SecurityLabel b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }
}