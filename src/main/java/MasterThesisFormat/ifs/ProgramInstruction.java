package MasterThesisFormat.ifs;

import MasterThesisFormat.instruction.OpCode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ProgramInstruction {

    private int id;
    private final OpCode OpCode;
    private final Register dest;
    private final Register src1;
    private final Register src2;
    private final byte input1;
    private final byte input2;
    private final Register condition;
    private final List<ProgramInstruction> thenBranch;
    private final List<ProgramInstruction> elseBranch;

    private ProgramInstruction(OpCode OpCode, Register dest, Register src1, Register src2,
                               byte input1, byte input2, Register condition,
                               List<ProgramInstruction> thenBranch, List<ProgramInstruction> elseBranch) {
        this.OpCode = OpCode;
        this.dest = dest;
        this.src1 = src1;
        this.src2 = src2;
        this.input1 = input1;
        this.input2 = input2;
        this.condition = condition;
        this.thenBranch = thenBranch == null ? Collections.emptyList() : thenBranch;
        this.elseBranch = elseBranch == null ? Collections.emptyList() : elseBranch;
    }

    public ProgramInstruction StoreBytes(Register src, byte length, Register dest) {
        return new ProgramInstruction(OpCode.STORE_BYTES, dest, src, null, length, (byte) 0, null, null, null);
    }

    public ProgramInstruction computeSharedSecret(Register src, Register dest) {
        return new ProgramInstruction(OpCode.COMPUTE_SHARED_SECRET, dest, src, null, (byte) 0, (byte) 0, null, null, null);
    }

    public ProgramInstruction hash(Register src, byte salt, Register dest) {
        return new ProgramInstruction(OpCode.HASH, dest, src, null, salt, (byte) 0, null, null, null);
    }

    public ProgramInstruction mac(Register srcKey, Register srcData, byte length, Register dest) {
        return new ProgramInstruction(OpCode.MAC, dest, srcKey, srcData, length, (byte) 0, null, null, null);
    }

    public ProgramInstruction verify(Register srcExpected, Register srcActual) {
        return new ProgramInstruction(OpCode.VERIFY, null, srcExpected, srcActual, (byte) 0, (byte) 0, null, null, null);
    }

    public ProgramInstruction exponent(Register src1, Register src2, Register destReg, byte length) {
        return new ProgramInstruction(OpCode.EXPONENT, destReg, src1, src2, length, (byte) 0, null, null, null);
    }

    public ProgramInstruction pad(Register src1, byte length, Register destReg) {
        return new ProgramInstruction(OpCode.PAD, destReg, src1, null, length, (byte) 0, null, null, null);
    }

    public ProgramInstruction prgGenerate(Register src,  Register destReg) {
        return new ProgramInstruction(OpCode.PRG_GENERATE, destReg, src1, null, (byte) 0, (byte) 0, null, null, null);
    }

    public ProgramInstruction xor(Register src1, Register src2, Register destReg) {
        return new ProgramInstruction(OpCode.XOR, destReg, src1, src2, (byte) 0, (byte) 0, null, null, null);
    }

    public ProgramInstruction decrypt(Register srcKey, Register srcInput, Register destReg) {
        return new ProgramInstruction(OpCode.DECRYPT, destReg, srcKey, srcInput, (byte) 0, (byte) 0, null, null, null);
    }

    public ProgramInstruction encrypt(Register srcKey, Register srcInput, Register destReg) {
        return new ProgramInstruction(OpCode.ENCRYPT, destReg, srcKey, srcInput, (byte) 0, (byte) 0, null, null, null);
    }

    public ProgramInstruction forward(Register srcID) {
        return new ProgramInstruction(OpCode.FORWARD, null, srcID, null, (byte) 0, (byte) 0, null, null, null);
    }

    public ProgramInstruction concate(Register src1, Register src2, Register destReg) {
        return new ProgramInstruction(OpCode.CONCATE, destReg, src1, src2, (byte) 0, (byte) 0, null, null, null);
    }

    public ProgramInstruction forLoop(byte times, byte instrCount) {
        return new ProgramInstruction(OpCode.CONCATE, null, null, null, times, instrCount, null, null, null);
    }


    public OpCode getOpCode() {
        return OpCode;
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