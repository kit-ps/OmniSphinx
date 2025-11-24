package OmniSphinx.ifs;

import java.util.List;

public class Report {
    private final List<Violation> violations;

    Report(List<Violation> violations) {
        this.violations = List.copyOf(violations);
    }

    public List<Violation> getViolations() {
        return violations;
    }

    public boolean isClean() {
        return violations.isEmpty();
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (violations.isEmpty()) {
            sb.append("No violations detected\n");
        } else {
            for (Violation v : violations) {
                sb.append("Violation (" + v.getType() + "): ")
                        .append(v.getMessage())
                        .append('\n');
            }
        }
        return sb.toString();
    }
}