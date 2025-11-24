import OmniSphinx.ifs.*;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class InformationSecurityTest {

    @Test
    public void analyzeSphinxRelayInstructions() {
        List<ProgramInstruction> program = new ArrayList<>();

        byte salt = 0x00;
        program.add(ProgramInstruction.concateWithByteValue(Register.R_SHARED_SECRET, salt, Register.R_SHARED_SECRET));

        program.add(ProgramInstruction.hash(Register.R_SHARED_SECRET, Register.R0));
        program.add(ProgramInstruction.decrypt(Register.R0, Register.R_PAYLOAD, Register.R_PAYLOAD));

        byte nextHop = 0x00;
        program.add(ProgramInstruction.load(nextHop, Register.R1));
        program.add(ProgramInstruction.forward(Register.R1));

        Map<Register, SecurityLabel> senderInputs = Map.of(
                Register.R_SHARED_SECRET, SecurityLabel.SECRET,
                Register.R1, SecurityLabel.PUBLIC
        );

        Analyzer analyzer = new Analyzer(Policy.senderClassified(senderInputs));
        Report report = analyzer.analyze(program);
        System.out.println(report.toString());
        assertTrue(report.isClean());
    }

    @Test
    public void analyzePolySphinxRelayInstructions() {
        List<ProgramInstruction> program = new ArrayList<>();

        byte sigma = 0x01;
        program.add(ProgramInstruction.load(sigma, Register.R0));
        program.add(ProgramInstruction.encrypt(Register.R0, Register.R_PAYLOAD, Register.R_PAYLOAD));

        byte nextHop = 0x02;
        program.add(ProgramInstruction.load(nextHop, Register.R1));
        program.add(ProgramInstruction.forward(Register.R1));

        Map<Register, SecurityLabel> senderInputs = Map.of(
                Register.R0, SecurityLabel.SECRET,
                Register.R1, SecurityLabel.PUBLIC
        );

        Analyzer analyzer = new Analyzer(Policy.senderClassified(senderInputs));
        Report report = analyzer.analyze(program);
        System.out.println(report.toString());
        assertTrue(report.isClean());
    }
}
