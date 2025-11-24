package OmniSphinx.ifs;

import java.util.*;

class Taint {
    SecurityLabel label;
    Set<Register> dataSecrets;
    Set<Register> controlSecrets;
    List<Integer> controlInstrs;

    Taint(SecurityLabel label) {
        this.label = label;
        this.dataSecrets = new HashSet<>();
        this.controlSecrets = new HashSet<>();
        this.controlInstrs = new ArrayList<>();
    }

    Taint copy() {
        Taint t = new Taint(label);
        t.dataSecrets.addAll(dataSecrets);
        t.controlSecrets.addAll(controlSecrets);
        t.controlInstrs.addAll(controlInstrs);
        return t;
    }

    static Taint join(Taint a, Taint b) {
        Taint t = new Taint(SecurityLabel.join(a.label, b.label));
        t.dataSecrets.addAll(a.dataSecrets);
        t.dataSecrets.addAll(b.dataSecrets);
        t.controlSecrets.addAll(a.controlSecrets);
        t.controlSecrets.addAll(b.controlSecrets);
        t.controlInstrs.addAll(a.controlInstrs);
        t.controlInstrs.addAll(b.controlInstrs);
        return t;
    }
}

/**
 * Holds the taint for all registers and the current program counter label.
 */
class TaintState {
    private final Map<Register, Taint> regs = new EnumMap<>(Register.class);
    private Taint pc = new Taint(SecurityLabel.PUBLIC);

    TaintState(Policy policy) {
        for (Register r : Register.values()) {
            SecurityLabel l = policy.getLabel(r);
            Taint t = new Taint(l);
            if (l == SecurityLabel.SECRET) {
                t.dataSecrets.add(r);
            }
            regs.put(r, t);
        }
    }

    TaintState copy() {
        TaintState s = new TaintState();
        for (Map.Entry<Register, Taint> e : regs.entrySet()) {
            s.regs.put(e.getKey(), e.getValue().copy());
        }
        s.pc = pc.copy();
        return s;
    }

    private TaintState() {
    }

    Taint get(Register r) {
        return regs.get(r);
    }

    void set(Register r, Taint t) {
        regs.put(r, t);
    }

    Taint getPc() {
        return pc;
    }

    void setPc(Taint t) {
        pc = t;
    }

    void merge(TaintState a, TaintState b) {
        for (Register r : regs.keySet()) {
            set(r, Taint.join(a.get(r), b.get(r)));
        }
        // pc label after merge is the existing pc (control joins handled in branches)
    }
}