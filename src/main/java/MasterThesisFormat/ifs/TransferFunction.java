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
}