package MasterThesisFormat.header;

public class InstructionHeader {
    private final byte[] instructions;
    private final byte[] initialRegisters;
    
    public InstructionHeader(byte[] instructions, byte[] initialRegisters) {
        this.instructions = instructions.clone();
        this.initialRegisters = initialRegisters.clone();
    }
    
    public byte[] getInstructions() {
        return instructions.clone();
    }
    
    public byte[] getInitialRegisters() {
        return initialRegisters.clone();
    }
}