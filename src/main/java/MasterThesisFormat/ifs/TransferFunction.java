package MasterThesisFormat.ifs;

import MasterThesisFormat.instruction.OpCode;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

public class TransferFunction {

    /** Functional interface representing a taint propagation rule. */
    @FunctionalInterface
    public interface Rule {
        void apply(ProgramInstruction ins, TaintState state, List<Violation> violations, Policy policy);
    }

    private final Map<OpCode, Rule> rules = new EnumMap<>(OpCode.class);

    public TransferFunction() {
        rules.put(OpCode.LOAD1, this::load);
        rules.put(OpCode.LOAD2, this::load);
        rules.put(OpCode.LOAD3, this::load);
        rules.put(OpCode.STORE_BYTES, this::storeBytes);
        rules.put(OpCode.CONCATE, this::concate);
        rules.put(OpCode.CONCATE_WITH_BYTE_VALUE, this::concateWithByteValue);
        rules.put(OpCode.XOR, this::xor);
        rules.put(OpCode.ADD, this::add);
        rules.put(OpCode.HASH, this::hash);
        rules.put(OpCode.PRG_GENERATE, this::prgGenerate);
        rules.put(OpCode.ENCRYPT, this::encrypt);
        rules.put(OpCode.DECRYPT, this::decrypt);
        rules.put(OpCode.MAC, this::mac);
        rules.put(OpCode.FOR, this::forLoop);
        rules.put(OpCode.EXPONENT, this::exponent);
        rules.put(OpCode.PAD, this::pad);
        rules.put(OpCode.COMPUTE_SHARED_SECRET, this::computeSharedSecret);
        rules.put(OpCode.FORWARD, this::forward);
        rules.put(OpCode.VERIFY, this::verify);
    }

    /** Applies the taint propagation rule for the given instruction. */
    public void apply(ProgramInstruction ins, TaintState state, List<Violation> violations, Policy policy) {
        Rule rule = rules.get(ins.getOpCode());
        if (rule != null) {
            rule.apply(ins, state, violations, policy);
        }
    }


    private void load(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = joinPc(state, new Taint(SecurityLabel.PUBLIC));
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void storeBytes(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = joinPc(state, state.get(ins.getSrc1()));
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void concate(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = joinPc(state, state.get(ins.getSrc1()), state.get(ins.getSrc2()));
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void concateWithByteValue(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = joinPc(state, state.get(ins.getSrc1())); // byte value is public
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void xor(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = joinPc(state, state.get(ins.getSrc1()), state.get(ins.getSrc2()));
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void add(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = joinPc(state, state.get(ins.getSrc1()), state.get(ins.getSrc2()));
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void hash(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = joinPc(state, state.get(ins.getSrc1()));
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void prgGenerate(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint key = state.get(ins.getSrc1());
        Taint length = ins.getSrc2() == null ? new Taint(SecurityLabel.PUBLIC) : state.get(ins.getSrc2());
        Taint res;
        if (key.label == SecurityLabel.SECRET) {
            res = joinPc(state, new Taint(SecurityLabel.PUBLIC_ALLOWED));
        } else {
            res = joinPc(state, key, length);
        }
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void encrypt(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint key = state.get(ins.getSrc1());
        Taint pt = state.get(ins.getSrc2());
        Taint res;
        if (key.label == SecurityLabel.SECRET) {
            res = joinPc(state, new Taint(SecurityLabel.PUBLIC_ALLOWED));
        } else {
            res = joinPc(state, key, pt);
        }
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void decrypt(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint key = state.get(ins.getSrc1());
        Taint pt = state.get(ins.getSrc2());
        Taint res;
        if (key.label == SecurityLabel.SECRET) {
            res = joinPc(state, new Taint(SecurityLabel.PUBLIC_ALLOWED));
        } else {
            res = joinPc(state, key, pt);
        }
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void mac(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint key = state.get(ins.getSrc1());
        Taint msg = state.get(ins.getSrc2());
        Taint res;
        if (key.label == SecurityLabel.SECRET) {
            res = joinPc(state, new Taint(SecurityLabel.PUBLIC_ALLOWED));
        } else {
            res = joinPc(state, key, msg);
        }
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void exponent(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = joinPc(state, state.get(ins.getSrc1()), state.get(ins.getSrc2()));
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void pad(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = joinPc(state, state.get(ins.getSrc1()));
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void computeSharedSecret(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Taint res = joinPc(state, state.get(ins.getSrc1()));
        state.set(ins.getDest(), res);
        checkSink(ins, res, v, policy);
    }

    private void verify(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        // result of verification is not stored but may influence control flow
        joinPc(state, state.get(ins.getSrc1()), state.get(ins.getSrc2()));
    }

    private void forward(ProgramInstruction ins, TaintState state, List<Violation> v, Policy policy) {
        Register nextHop = ins.getSrc1();

        Taint nextHopTaint = joinPc(state, state.get(nextHop));
        if (nextHopTaint.label != SecurityLabel.PUBLIC) {
            addViolation(ins, nextHop, nextHopTaint, v);
        }

        checkForwardReg(ins, Register.R_ALPHA, SecurityLabel.PUBLIC, state, v);
        checkForwardReg(ins, Register.R_BETA, SecurityLabel.PUBLIC_ALLOWED, state, v);
        checkForwardReg(ins, Register.R_GAMMA, SecurityLabel.PUBLIC_ALLOWED, state, v);
        checkForwardReg(ins, Register.R_PAYLOAD, SecurityLabel.PUBLIC_ALLOWED, state, v);
    }

    private void checkForwardReg(ProgramInstruction ins, Register r, SecurityLabel allowed, TaintState state, List<Violation> v) {
        Taint t = joinPc(state, state.get(r));
        boolean ok = (t.label == SecurityLabel.PUBLIC) || (allowed == SecurityLabel.PUBLIC_ALLOWED && t.label == SecurityLabel.PUBLIC_ALLOWED);
        if (!ok) {
            addViolation(ins, r, t, v);
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

    private Taint joinPc(TaintState state, Taint... taints) {
        Taint res = state.getPc().copy();
        for (Taint t : taints) {
            if (t != null) {
                res = Taint.join(res, t);
            }
        }
        return res;
    }

    private void addViolation(ProgramInstruction ins, Register dest, Taint res, List<Violation> v) {
        Violation.Type type;
        Register src;
        if (!res.dataSecrets.isEmpty()) {
            type = Violation.Type.EXPLICIT;
            src = res.dataSecrets.iterator().next();
        } else if (!res.controlSecrets.isEmpty()) {
            type = Violation.Type.IMPLICIT;
            src = res.controlSecrets.iterator().next();
        } else {
            type = Violation.Type.EXPLICIT;
            src = dest; // unknown origin
        }
        List<Integer> ids = new ArrayList<>(res.controlInstrs);
        ids.add(ins.getId());
        v.add(new Violation(type, src, dest, ids));
    }

    private void checkSink(ProgramInstruction ins, Taint res, List<Violation> v, Policy policy) {
        Register dest = ins.getDest();
        if (dest != null && policy.isPublicOutput(dest) && res.label == SecurityLabel.SECRET) {
            addViolation(ins, dest, res, v);
        }
    }
}