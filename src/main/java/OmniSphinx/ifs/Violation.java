package OmniSphinx.ifs;

import java.util.List;

public class Violation {
    public enum Type {EXPLICIT, IMPLICIT}

    private final Type type;
    private final Register source;
    private final Register sink;
    private final List<Integer> instructionIds;

    Violation(Type type, Register source, Register sink, List<Integer> instructionIds) {
        this.type = type;
        this.source = source;
        this.sink = sink;
        this.instructionIds = List.copyOf(instructionIds);
    }

    public Type getType() {
        return type;
    }

    public Register getSource() {
        return source;
    }

    public Register getSink() {
        return sink;
    }

    public List<Integer> getInstructionIds() {
        return instructionIds;
    }

    public String getMessage() {
        String path = instructionIds.toString();
        return "The input " + source + " flows to " + sink + " via instructions " + path +
                " (" + type + ")";
    }
}