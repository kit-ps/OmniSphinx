import MasterThesisFormat.ifs.*;
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

    @Test
    public void analyzePolySphinxRelayInstructions() throws Exception {
        List<ProgramInstruction> program = new ArrayList<>();

        byte sigma = 0x01;
        program.add(ProgramInstruction.load(sigma, Register.R0));
        program.add(ProgramInstruction.encrypt(Register.R0, Register.R_PAYLOAD, Register.R_PAYLOAD));

        byte nextHop = 0x02;
        program.add(ProgramInstruction.load(nextHop, Register.R1));
        program.add(ProgramInstruction.forward(Register.R1));

        Analyzer analyzer = new Analyzer(Policy.defaultPolicy());
        Report report = analyzer.analyze(program);
        System.out.println(report.toString());
        assertTrue(report.isClean());
    }

    @Test
    public void analyzePolySphinxExitInstructions() throws Exception {
        List<ProgramInstruction> program = new ArrayList<>();

        program.add(ProgramInstruction.load((byte) 0x01, Register.R2)); //R2 = REG_SEED
        program.add(ProgramInstruction.load((byte) 0x02, Register.R3)); //R3 = REG_PATH
        program.add(ProgramInstruction.load((byte) 0x03, Register.R4)); //R4 = REG_RECIPIENT

        program.add(ProgramInstruction.hash(Register.R2, Register.R0)); //R0 = REG_SIGMNA
        program.add(ProgramInstruction.concate(Register.R5, Register.R0, Register.R5)); // R5 = REG_KEYS

        List<ProgramInstruction> loop1 = new ArrayList<>();
        loop1.add(ProgramInstruction.StoreBytes(Register.R3, (byte) 1, Register.R6)); //R6 = REG_P_I_J
        loop1.add(ProgramInstruction.add(Register.R0, Register.R6, Register.R0));
        loop1.add(ProgramInstruction.hash(Register.R0, Register.R0));
        loop1.add(ProgramInstruction.hash(Register.R0, Register.R0));
        loop1.add(ProgramInstruction.concate(Register.R0, Register.R5, Register.R5));
        program.add(ProgramInstruction.forLoop((byte) 0x01, loop1));

        List<ProgramInstruction> loop2 = new ArrayList<>();
        loop2.add(ProgramInstruction.StoreBytes(Register.R5, (byte) 1, Register.R0));
        loop2.add(ProgramInstruction.decrypt(Register.R0, Register.R_PAYLOAD, Register.R_PAYLOAD));
        program.add(ProgramInstruction.forLoop((byte) 0x02, loop2));

        program.add(ProgramInstruction.forward(Register.R4));

        Analyzer analyzer = new Analyzer(Policy.defaultPolicy());
        Report report = analyzer.analyze(program);
        System.out.println(report.toString());
        assertTrue(report.isClean());
    }

    @Test
    public void analyzePolySphinxReplicationInstructions() throws Exception {
        List<ProgramInstruction> program = new ArrayList<>();

        program.add(ProgramInstruction.load((byte) 0x10, Register.R7)); //R7 = REG_SUBHEADER

        List<ProgramInstruction> loop = new ArrayList<>();
        loop.add(ProgramInstruction.StoreBytes(Register.R7, (byte) 1, Register.R1)); //R1 = REG_NEXT_HOP
        loop.add(ProgramInstruction.StoreBytes(Register.R7, (byte) 1, Register.R8)); //R8 = REG_KEY
        loop.add(ProgramInstruction.StoreBytes(Register.R7, (byte) 2, Register.R9)); //R9 = REG_ALPHA
        loop.add(ProgramInstruction.StoreBytes(Register.R7, (byte) 1, Register.R12)); //REG_GAMMA
        loop.add(ProgramInstruction.StoreBytes(Register.R7, (byte) 1, Register.R13)); //REG_BETA
        loop.add(ProgramInstruction.encrypt(Register.R8, Register.R_PAYLOAD, Register.R_PAYLOAD));
        loop.add(ProgramInstruction.forward(Register.R1));
        program.add(ProgramInstruction.forLoop((byte) 0x01, loop));

        Analyzer analyzer = new Analyzer(Policy.defaultPolicy());
        Report report = analyzer.analyze(program);
        System.out.println(report.toString());
        assertTrue(report.isClean());
    }
}
