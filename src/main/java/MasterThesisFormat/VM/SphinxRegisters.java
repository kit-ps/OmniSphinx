package MasterThesisFormat.VM;

import java.util.EnumMap;
import java.util.Map;

/**
 * Eine einfache Register-Verwaltung: Jeder RegisterType wird
 * einem Byte-Array zugeordnet.
 */
public class SphinxRegisters {
    private final Map<RegisterType, byte[]> registers;

    public SphinxRegisters() {
        this.registers = new EnumMap<>(RegisterType.class);
    }

    /**
     * Speichert value im gegebenen Register.
     */
    public void store(RegisterType type, byte[] value) throws VMException {
        if (value == null) {
            throw new VMException("Wert für Register " + type + " darf nicht null sein");
        }
        // Kopie erstellen, um Seiteneffekte zu vermeiden
        registers.put(type, value.clone());
    }

    /**
     * Liest den Inhalt eines Registers.
     * Wir geben immer eine Kopie zurück.
     */
    public byte[] load(RegisterType type) throws VMException {
        byte[] value = registers.get(type);
        if (value == null) {
            throw new VMException("Register " + type + " ist nicht initialisiert");
        }
        return value.clone();
    }

    /**
     * Löscht den Inhalt eines einzelnen Registers.
     */
    public void clear(RegisterType type) {
        registers.remove(type);
    }

    /**
     * Löscht alle Register.
     */
    public void clearAll() {
        registers.clear();
    }
}
