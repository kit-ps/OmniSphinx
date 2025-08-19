import MasterThesisFormat.ifs.*;
import MasterThesisFormat.instruction.Instruction;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertTrue;

public class InformationSecurityTest {

    @Test
    public void analyzeSphinxInstructions() throws Exception {
        List<ProgramInstruction> program = new ArrayList<>();

        byte salt = 0x00;
        program.add(ProgramInstruction.concateWithByteValue(Register.R_SHARED_SECRET, salt, Register.R_SHARED_SECRET));

        program.add(ProgramInstruction.hash(Register.R_SHARED_SECRET, Register.R0));
        program.add(ProgramInstruction.decrypt(Register.R0, Register.R_PAYLOAD, Register.R_PAYLOAD));

        byte nextHop = 0x00;
        program.add(ProgramInstruction.load(nextHop, Register.R1));
        program.add(ProgramInstruction.forward(Register.R1));

        Analyzer analyzer = new Analyzer(Policy.defaultPolicy());
        Report report = analyzer.analyze(program);
        System.out.println(report.toString());
        assertTrue(report.isClean());
    }
}
