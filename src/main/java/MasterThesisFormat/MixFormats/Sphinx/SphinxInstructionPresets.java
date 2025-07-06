package MasterThesisFormat.MixFormats.Sphinx;

import MasterThesisFormat.instruction.Instruction;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class SphinxInstructionPresets {

    // Register-Definitionen
    private static final byte REG_PAYLOAD     = 0x00;
    private static final byte REG_SHARED_SECRET     = 0x01;
    private static final byte REG_HASH_PAYLOAD     = 0x03;

    public static byte[] createInstructions(byte nextHop) throws IOException {
        ByteArrayOutputStream instr = new ByteArrayOutputStream();

        //Payload entschlüsseln
        instr.write(Instruction.hash(REG_SHARED_SECRET, REG_HASH_PAYLOAD));
        instr.write(Instruction.decrypt(REG_HASH_PAYLOAD, REG_PAYLOAD,  REG_PAYLOAD));

        //TODO: Sollte Blinding hier rein?!

        //Mixen


        //Paket an nächste Node weiterleiten
        //TODO: nexthop maybe ein byte[]? Mit Store befehl den reinladen und dann nextHop auf den Register?
        instr.write(Instruction.forward(nextHop));

        return instr.toByteArray();
    }
}
