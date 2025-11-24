package OmniSphinx.VM;

import java.util.Map;

public class VMContext {
    public Map<Byte, byte[]> registers;

    public VMContext(Map<Byte, byte[]> registers) {
        this.registers = registers;
    }
}
