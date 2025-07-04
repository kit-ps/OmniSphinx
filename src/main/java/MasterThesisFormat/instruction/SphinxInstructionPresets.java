package MasterThesisFormat.instruction;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SphinxInstructionPresets {

    // Register-Definitionen
    private static final byte REG_PAYLOAD     = 0x00;
    private static final byte REG_SHARED_SECRET     = 0x01;
    private static final byte REG_NEXT_HOP     = 0x02;
    private static final byte REG_HASH_PAYLOAD     = 0x03;

    public static byte[] createInstructions() throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        //Payload entschlüsseln
        instr.write(Instruction.hash(REG_SHARED_SECRET, REG_HASH_PAYLOAD));
        instr.write(Instruction.decrypt(REG_HASH_PAYLOAD, REG_PAYLOAD,  REG_PAYLOAD));

        //Mixen


        //Paket an nächste Node weiterleiten
        instr.write(Instruction.forward(REG_NEXT_HOP, REG_PAYLOAD));

        return instr.toByteArray();
    }
}
