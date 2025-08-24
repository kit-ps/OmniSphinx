package MasterThesisFormat.ifs;

import MasterThesisFormat.instruction.OpCode;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public class TransferFunction {

    /**
     * Functional interface representing a taint propagation rule.
     */
    @FunctionalInterface
    public interface Rule {
        void apply(ProgramInstruction ins, TaintState state, List<Violation> violations, Policy policy);
    }

    private final Map<OpCode, Rule> rules = new EnumMap<>(OpCode.class);

    public TransferFunction() {
        rules.put(OpCode.STORE_BYTES, this::storeBytes);
        rules.put(OpCode.ENCRYPT, this::encrypt);
        rules.put(OpCode.DECRYPT, this::decrypt);
        rules.put(OpCode.MAC, this::mac);
        rules.put(OpCode.FOR, this::forLoop);
    }

    public void apply(ProgramInstruction ins, TaintState state, List<Violation> violations, Policy policy) {
        Rule rule = rules.get(ins.getOpCode());
        if (rule != null) {
            rule.apply(ins, state, violations, policy);
        }
    }

    private void storeBytes(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = Taint.join(state.get(ins.getSrc1()), state.getPc());
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void encrypt(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = Taint.join(new Taint(SecurityLabel.PUBLIC), state.getPc());
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void decrypt(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = Taint.join(new Taint(SecurityLabel.PUBLIC), state.getPc());
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void mac(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = Taint.join(new Taint(SecurityLabel.PUBLIC), state.getPc());
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void checkSink(ProgramInstruction ins, Taint res, List<Violation> v, Policy policy) {
        Register dest = ins.getDest();
        if (policy.isPublicOutput(dest) && res.label == SecurityLabel.SECRET) {
            Violation.Type type = res.dataSecrets.isEmpty() ? Violation.Type.IMPLICIT : Violation.Type.EXPLICIT;
            Register src = res.dataSecrets.isEmpty() ? res.controlSecrets.iterator().next()
                    : res.dataSecrets.iterator().next();
            List<Integer> ids = res.controlInstrs.stream().toList();
            ids = new java.util.ArrayList<>(ids); ids.add(ins.getId());
            v.add(new Violation(type, src, dest, ids));
        }
    }

    private void forLoop(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Register countReg = ins.getSrc1();
        List<ProgramInstruction> body = ins.getThenBranch();
        if (countReg == null || body.isEmpty()) {
            return;
        }

        Taint oldPc = state.getPc().copy();
        Taint count = state.get(countReg);
        Taint loopPc = oldPc.copy();
        loopPc.label = SecurityLabel.join(loopPc.label, count.label);
        loopPc.controlSecrets.addAll(count.dataSecrets);
        loopPc.controlSecrets.addAll(count.controlSecrets);
        loopPc.controlInstrs.addAll(count.controlInstrs);
        loopPc.controlInstrs.add(ins.getId());

        TaintState loopState = state.copy();
        loopState.setPc(loopPc);

        final int MAX_ITERS = 5;
        int iter = 0;
        while (true) {
            TaintState before = loopState.copy();
            for (ProgramInstruction b : body) {
                apply(b, loopState, v, policy);
            }
            if (taintStateEquals(before, loopState)) {
                break;
            }
            iter++;
            if (iter >= MAX_ITERS) {
                for (Register r : Register.values()) {
                    Taint t = loopState.get(r);
                    t.label = SecurityLabel.SECRET;
                }
                loopState.setPc(new Taint(SecurityLabel.SECRET));
                break;
            }
        }

        for (Register r : Register.values()) {
            state.set(r, loopState.get(r));
        }
        state.setPc(oldPc);
    }

    private boolean taintStateEquals(TaintState a, TaintState b) {
        for (Register r : Register.values()) {
            Taint ta = a.get(r);
            Taint tb = b.get(r);
            if (ta.label != tb.label ||
                    !ta.dataSecrets.equals(tb.dataSecrets) ||
                    !ta.controlSecrets.equals(tb.controlSecrets)) {
                return false;
            }
        }
        Taint apc = a.getPc();
        Taint bpc = b.getPc();
        return apc.label == bpc.label &&
                apc.dataSecrets.equals(bpc.dataSecrets) &&
                apc.controlSecrets.equals(bpc.controlSecrets);
    }

}