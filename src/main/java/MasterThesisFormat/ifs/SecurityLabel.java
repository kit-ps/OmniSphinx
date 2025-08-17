package MasterThesisFormat.ifs;

public enum SecurityLabel {
    PUBLIC,
    UNKNOWN,
    SECRET;

    /**
     * Computes the least upper bound of two labels.
     */
    public static SecurityLabel join(SecurityLabel a, SecurityLabel b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }
}