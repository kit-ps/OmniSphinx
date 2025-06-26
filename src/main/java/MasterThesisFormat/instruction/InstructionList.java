package MasterThesisFormat.instruction;

import java.util.ArrayList;
import java.util.List;

public class InstructionList {
    private final List<Instruction> instructions;
    
    public InstructionList() {
        this.instructions = new ArrayList<>();
    }
    
    public void addInstruction(Instruction instruction) {
        instructions.add(instruction);
    }
    
    public List<Instruction> getInstructions() {
        return new ArrayList<>(instructions);
    }
    
    public byte[] serialize() {
        // Implementierung der Serialisierung
        return new byte[0]; // TODO
    }
    
    public static InstructionList deserialize(byte[] data) {
        // Implementierung der Deserialisierung
        return new InstructionList(); // TODO
    }
}