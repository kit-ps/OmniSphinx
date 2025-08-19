package MasterThesisFormat.ifs;

import java.util.*;

public class Policy {

    private final Map<Register, SecurityLabel> initial;
    private final Set<Register> publicOutputs;

    private Policy(Map<Register, SecurityLabel> initial, Set<Register> publicOutputs) {
        this.initial = initial;
        this.publicOutputs = publicOutputs;
    }

    /**
     * Returns the initial label for a register. Registers not mentioned in the
     * policy default to {@link SecurityLabel#UNKNOWN}.
     */
    public SecurityLabel getLabel(Register r) {
        return initial.getOrDefault(r, SecurityLabel.UNKNOWN);
    }

    /**
     * Returns whether the register is considered a public output sink.
     */
    public boolean isPublicOutput(Register r) {
        return publicOutputs.contains(r);
    }

    /**
     * Builder for policies.
     */
    public static class Builder {
        private final Map<Register, SecurityLabel> initial = new EnumMap<>(Register.class);
        private final Set<Register> publicOutputs = new HashSet<>();

        public Builder secret(Register r) {
            initial.put(r, SecurityLabel.SECRET);
            return this;
        }

        public Builder publicOutput(Register r) {
            initial.put(r, SecurityLabel.PUBLIC);
            publicOutputs.add(r);
            return this;
        }

        public Builder label(Register r, SecurityLabel l) {
            initial.put(r, l);
            return this;
        }

        public Policy build() {
            return new Policy(Collections.unmodifiableMap(initial),
                    Collections.unmodifiableSet(publicOutputs));
        }
    }

    /**
     * Creates a policy with the default rules described in the thesis.
     */
    public static Policy defaultPolicy() {
        return new Builder()
                .secret(Register.R_SHARED_SECRET)
                .publicOutput(Register.R_ALPHA)
                .publicOutput(Register.R_BETA)
                .publicOutput(Register.R_GAMMA)
                .publicOutput(Register.R_PAYLOAD)
                .build();
    }
}