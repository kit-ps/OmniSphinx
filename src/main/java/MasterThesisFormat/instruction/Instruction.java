package MasterThesisFormat.instruction;


import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class Instruction {

    /**
     * Extrahiert Bits aus einem Quellregister und speichert sie in einem Zielregister.
     * Die extrahierten Bits werden aus dem Quellregister entfernt.
     * @param source Quellregister, aus dem gelesen wird
     * @param length Anzahl an bytes die ausgewählt werden, angefangen vom 0ten byte
     * @param destReg Zielregister für die extrahierten Bits
     * @return Instruction für die Bit-Extraktion
     */
    public static byte[] storeBytes(byte source,  byte length, byte destReg) {
        return new byte[]{OpCode.STORE_BYTES.getCode(), source,  length, destReg};
    }

    public static byte[] storeMultipleBytes(byte source,  byte lengthReg, byte destReg) {
        return new byte[]{OpCode.STORE_MULTIPLE_BYTES.getCode(), source,  lengthReg, destReg};
    }

    /**
     * Berechnet ein gemeinsames Geheimnis (Shared Secret) aus einem öffentlichen Schlüssel.
     * Verwendet den privaten Schlüssel der Node und den übergebenen öffentlichen Schlüssel.
     * @param pubKeyReg Register mit dem öffentlichen Schlüssel (Alpha)
     * @param destReg Zielregister für das berechnete Shared Secret
     * @return Instruction für die Shared-Secret-Berechnung
     */
    public static byte[] computeSharedSecret(byte pubKeyReg, byte destReg) {
        return new byte[]{OpCode.COMPUTE_SHARED_SECRET.getCode(), pubKeyReg, destReg};
    }

    /**
     * Berechnet einen Hash-Wert aus dem Inhalt eines Registers.
     * @param inputReg Eingaberegister mit zu hashenden Daten
     * @param destReg Zielregister für den Hash-Wert
     * @return Instruction für die Hash-Berechnung
     */
    public static byte[] hash(byte inputReg, byte destReg) {
        return new byte[]{OpCode.HASH.getCode(), inputReg,  destReg};
    }



    /**
     * Berechnet einen MAC (Message Authentication Code) über Daten.
     * @param keyReg Register mit dem MAC-Schlüssel
     * @param dataReg Register mit den zu authentifizierenden Daten
     * "destReg Zielregister für den MAC-Wert"
     * @return Instruction für die MAC-Berechnung
     */
    public static byte[] mac(byte keyReg, byte dataReg, byte destReg) {
        return new byte[]{OpCode.MAC.getCode(), keyReg, dataReg, destReg};
    }

    /**
     * Überprüft, ob ein berechneter Wert mit einem erwarteten Wert übereinstimmt.
     * Wirft eine Exception, wenn die Werte nicht übereinstimmen.
     * @param expectedReg Register mit dem erwarteten Wert
     * @param computedReg Register mit dem berechneten Wert
     * @return Instruction für die Werte-Verifikation
     */
    public static byte[] verify(byte expectedReg, byte computedReg) {
        return new byte[]{OpCode.VERIFY.getCode(), expectedReg, computedReg};
    }

    /**
     * Berechnet eine Exponentation in der zugrunde liegenden Gruppe.
     * Wird für Blinding-Operationen verwendet.
     * @param inputReg1 Basis (Alpha)
     * @param inputReg2 Exponent (Binding-Faktor)
     * @param destReg Zielregister für das Ergebnis
     * @return Instruction für die Exponentation
     */
    public static byte[] exponent(byte inputReg1, byte inputReg2, byte destReg,  byte outputlength) {
        return new byte[]{OpCode.EXPONENT.getCode(), inputReg1, inputReg2, destReg, outputlength};
    }

    /**
     * Fügt Padding zu Daten hinzu, um eine bestimmte Länge zu erreichen.
     * @param inputReg Register mit den Original-Daten
     * @param Length Gewünschte Länge die gepadded werden wollte
     * @param destReg Zielregister für die gepadten Daten
     * @return Instruction für das Padding
     */
    public static byte[] pad(byte inputReg, byte Length, byte destReg) {
        return new byte[]{OpCode.PAD.getCode(), inputReg, Length, destReg};
    }

    /**
     * Generiert einen Keystream mittels PRG (Pseudo-Random Generator).
     *
     * @param seedReg Register mit dem Seed für den PRG
     * @param destReg Zielregister für den generierten Keystream
     * @return Instruction für die PRG-Generation
     */
    public static byte[] prgGenerate(byte seedReg, byte lengthReg,  byte destReg) {
        return new byte[]{OpCode.PRG_GENERATE.getCode(), seedReg, lengthReg, destReg};
    }

    /**
     * Führt eine XOR-Operation zwischen zwei Registern durch.
     * Wird für die Entschlüsselung von Beta verwendet.
     * @param inputA Erstes Eingaberegister
     * @param inputB Zweites Eingaberegister
     * @param destReg Zielregister für das XOR-Ergebnis
     * @return Instruction für die XOR-Operation
     */
    public static byte[] xor(byte inputA, byte inputB, byte destReg) {
        return new byte[]{OpCode.XOR.getCode(), inputA, inputB, destReg};
    }

    /**
     * Entschlüsselt Daten mit einem gegebenen Schlüssel.
     * @param keyReg Register mit dem Entschlüsselungsschlüssel
     * @param inputReg Register mit den verschlüsselten Daten
     * @param destReg Zielregister für die entschlüsselten Daten
     * @return Instruction für die Entschlüsselung
     */
    public static byte[] decrypt(byte keyReg, byte inputReg, byte destReg) {
        return new byte[]{OpCode.DECRYPT.getCode(), keyReg, inputReg, destReg};
    }

    /**
     * Verschlüsselt Daten mit einem gegebenen Schlüssel.
     * @param keyReg Register mit dem Entschlüsselungsschlüssel
     * @param inputReg Register mit den Daten
     * @param destReg Zielregister für die verschlüsselten Daten
     * @return Instruction für die Entschlüsselung
     */
    public static byte[] encrypt(byte keyReg, byte inputReg, byte destReg) {
        return new byte[]{OpCode.ENCRYPT.getCode(), keyReg, inputReg, destReg};
    }

    /**
     * Leitet ein Paket an den ncäshten Node.
     *
     * @param idReg Register mit der ID der nächsten Node
     * @return Instruction für das Forwarding
     */
    public static byte[] forward(byte idReg) {
        return new byte[]{OpCode.FORWARD.getCode(), idReg};
    }


    public static byte[] concate(byte reg1, byte reg2, byte destReg) {
        return new byte[] {OpCode.CONCATE.getCode() ,reg1, reg2, destReg };
    }

    public static byte[] concateWithByteValue(byte reg1, byte value, byte destReg) {
        return new byte[] {OpCode.CONCATE_WITH_BYTE_VALUE.getCode() ,reg1, value, destReg };
    }

    public static byte[] forLoop(byte times, byte instrCount) {
        return new byte[]{OpCode.FOR.getCode(), times, instrCount};
    }

    public static byte[] mixNone() {
        return new byte[]{OpCode.MIX_NONE.getCode()};
    }

    public static byte[] mixTimed(byte delay) {
        return new byte[]{OpCode.MIX_TIMED.getCode(), delay};
    }

    public static byte[] mixThreshold(byte bufferSize) {
        return new byte[]{OpCode.MIX_THRESHOLD.getCode(), bufferSize};
    }

    public static byte[] mixPool(byte poolSize, byte outflowRate) {
        return new byte[]{OpCode.MIX_POOL.getCode(), poolSize, outflowRate};
    }

    public static byte[] mixPoisson(byte meanDelay) {
        return new byte[]{OpCode.MIX_POISSON.getCode(), meanDelay};
    }

    public static byte[] load(byte[] value, byte register) throws IOException {
        int length = value.length;
        if(length <= 0xFF) {
            return load1(value, register);
        } else if(length <= 0xFFFF) {
            return load2(value, register);
        } else if(length <= 0xFFFFFF) {
            return load3(value, register);
        } else {
            throw new IOException("Invalid length for load operation");
        }
    }

    public static byte[] load1(byte[] value, byte register) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(OpCode.LOAD1.getCode());
        out.write(value.length);
        out.write(value);
        out.write(register);
        return out.toByteArray();
    }

    public static byte[] load2(byte[] value, byte register) throws IOException {
        int length = value.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(OpCode.LOAD2.getCode());
        out.write((length >> 8) & 0xFF);
        out.write(length & 0xFF);
        out.write(value);
        out.write(register);
        return out.toByteArray();
    }

    public static byte[] load3(byte[] value, byte register) throws IOException {
        int length = value.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(OpCode.LOAD3.getCode());
        out.write((length >> 16) & 0xFF);
        out.write((length >> 8) & 0xFF);
        out.write(length & 0xFF);
        out.write(value);
        out.write(register);
        return out.toByteArray();
    }

    public static byte[] addRight(byte Register, byte addition, byte dest) {
        return new byte[]{OpCode.ADD.getCode(), Register, addition, dest};
    }
}