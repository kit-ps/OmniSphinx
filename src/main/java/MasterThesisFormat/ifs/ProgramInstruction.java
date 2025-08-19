package MasterThesisFormat.ifs;

import MasterThesisFormat.instruction.OpCode;

import java.util.Collections;
import java.util.List;

public class ProgramInstruction {

    private int id;
    private  final OpCode code;
    private final Register dest;
    private final Register src1;
    private final Register src2;
    private final Byte input1;
    private final Byte input2;
    private final Register condition;
    private final List<ProgramInstruction> thenBranch;
    private final List<ProgramInstruction> elseBranch;

    private ProgramInstruction(OpCode OpCode, Register dest, Register src1, Register src2,
                               Byte input1, Byte input2, Register condition,
                               List<ProgramInstruction> thenBranch, List<ProgramInstruction> elseBranch) {
        this.code = OpCode;
        this.dest = dest;
        this.src1 = src1;
        this.src2 = src2;
        this.input1 = input1;
        this.input2 = input2;
        this.condition = condition;
        this.thenBranch = thenBranch == null ? Collections.emptyList() : thenBranch;
        this.elseBranch = elseBranch == null ? Collections.emptyList() : elseBranch;
    }

    public static ProgramInstruction StoreBytes(Register src, byte length, Register dest) {
        return new ProgramInstruction(OpCode.STORE_BYTES, dest, src, null, length, null, null, null, null);
    }

    public static ProgramInstruction computeSharedSecret(Register src, Register dest) {
        return new ProgramInstruction(OpCode.COMPUTE_SHARED_SECRET, dest, src, null, null, null, null, null, null);
    }

    public static ProgramInstruction hash(Register src,  Register dest) {
        return new ProgramInstruction(OpCode.HASH, dest, src, null, null, null, null, null, null);
    }

    public static ProgramInstruction mac(Register srcKey, Register srcData, byte length, Register dest) {
        return new ProgramInstruction(OpCode.MAC, dest, srcKey, srcData, length, null, null, null, null);
    }

    public static ProgramInstruction verify(Register srcExpected, Register srcActual) {
        return new ProgramInstruction(OpCode.VERIFY, null, srcExpected, srcActual, null, null, null, null, null);
    }

    public static ProgramInstruction exponent(Register src1, Register src2, Register destReg, byte length) {
        return new ProgramInstruction(OpCode.EXPONENT, destReg, src1, src2, length, null, null, null, null);
    }

    public static ProgramInstruction pad(Register src1, byte length, Register destReg) {
        return new ProgramInstruction(OpCode.PAD, destReg, src1, null, length, null, null, null, null);
    }

    public static ProgramInstruction prgGenerate(Register src1,  Register destReg) {
        return new ProgramInstruction(OpCode.PRG_GENERATE, destReg, src1, null, null, null, null, null, null);
    }

    public static ProgramInstruction xor(Register src1, Register src2, Register destReg) {
        return new ProgramInstruction(OpCode.XOR, destReg, src1, src2, null, null, null, null, null);
    }

    public static ProgramInstruction decrypt(Register srcKey, Register srcInput, Register destReg) {
        return new ProgramInstruction(OpCode.DECRYPT, destReg, srcKey, srcInput, null, null, null, null, null);
    }

    public static ProgramInstruction encrypt(Register srcKey, Register srcInput, Register destReg) {
        return new ProgramInstruction(OpCode.ENCRYPT, destReg, srcKey, srcInput, null, null, null, null, null);
    }

    public static ProgramInstruction forward(Register srcID) {
        return new ProgramInstruction(OpCode.FORWARD, null, srcID, null, null, null, null, null, null);
    }

    public static ProgramInstruction concate(Register src1, Register src2, Register destReg) {
        return new ProgramInstruction(OpCode.CONCATE, destReg, src1, src2, null, null, null, null, null);
    }

    public static ProgramInstruction forLoop(byte times, byte instrCount) {
        return new ProgramInstruction(OpCode.CONCATE, null, null, null, times, instrCount, null, null, null);
    }

    public static ProgramInstruction concateWithByteValue(Register src1, byte value, Register destReg) {
        return new ProgramInstruction(OpCode.CONCATE, destReg, src1, null, value, null, null, null, null);
    }

    public static ProgramInstruction load(byte value, Register dest) {
        return new ProgramInstruction(OpCode.LOAD, dest, null, null, value, null, null, null, null);
    }



    public OpCode getOpCode() {
        return code;
    }

    public void setId(int id) {
        this.id = id;
    }


    public int getId() {
        return id;
    }


    public Register getDest() {
        return dest;
    }

    public Register getSrc1() {
        return src1;
    }

    public Register getSrc2() {
        return src2;
    }

    public Register getCondition() {
        return condition;
    }

    public List<ProgramInstruction> getThenBranch() {
        return thenBranch;
    }

    public List<ProgramInstruction> getElseBranch() {
        return elseBranch;
    }

    public byte getInput1() {
        return input1;
    }

    public byte getInput2() {
        return input2;
    }
}