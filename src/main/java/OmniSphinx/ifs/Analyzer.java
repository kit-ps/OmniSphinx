package OmniSphinx.ifs;

import java.util.ArrayList;
import java.util.List;

public class Analyzer {

    private final Policy policy;
    private final TransferFunction tf = new TransferFunction();

    public Analyzer(Policy policy) {
        this.policy = policy;
    }

    /**
     * Analyses the given instruction list and returns a report with all
     * discovered violations.
     */
    public Report analyze(List<ProgramInstruction> program) {
        TaintState state = new TaintState(policy);
        List<Violation> violations = new ArrayList<>();
        int counter = 1;
        analyzeSeq(program, state, violations, counter);
        return new Report(violations);
    }

    private void analyzeSeq(List<ProgramInstruction> program, TaintState state,
                            List<Violation> violations, int counter) {
        for (ProgramInstruction ins : program) {
            ins.setId(counter);
            counter++;
            switch (ins.getOpCode()) {
                default -> tf.apply(ins, state, violations, policy);
            }
        }
    }

    private void analyzeIf(ProgramInstruction ins, TaintState state,
                           List<Violation> violations, int counter) {
        Taint cond = state.get(ins.getCondition());
        Taint newPc = state.getPc().copy();
        newPc.label = SecurityLabel.join(newPc.label, cond.label);
        newPc.controlSecrets.addAll(cond.dataSecrets);
        newPc.controlSecrets.addAll(cond.controlSecrets);
        newPc.controlInstrs.addAll(cond.controlInstrs);
        newPc.controlInstrs.add(ins.getId());

        TaintState thenState = state.copy();
        thenState.setPc(newPc.copy());
        analyzeSeq(ins.getThenBranch(), thenState, violations, counter);

        TaintState elseState = state.copy();
        elseState.setPc(newPc.copy());
        analyzeSeq(ins.getElseBranch(), elseState, violations, counter);

        state.merge(thenState, elseState);
    }
}
