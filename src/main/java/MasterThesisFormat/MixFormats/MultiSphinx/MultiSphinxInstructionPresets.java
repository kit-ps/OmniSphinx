package MasterThesisFormat.MixFormats.MultiSphinx;

import MasterThesisFormat.instruction.Instruction;
import MasterThesisFormat.instruction.InstructionRegister;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class MultiSphinxInstructionPresets {
	// Register-Definitionen
	private static final byte REG_PAYLOAD = InstructionRegister.PAYLOAD.getCode();
	private static final byte REG_ALPHA = InstructionRegister.NEXT_ALPHA.getCode();
	private static final byte REG_BETA = InstructionRegister.NEXT_INSTRUCTIONS.getCode();
	private static final byte REG_GAMMA = InstructionRegister.MAC.getCode();
	private static final byte REG_SHARED_SECRET = InstructionRegister.SHARED_SECRET.getCode();
	private static final byte REG_NEXT_HOP = InstructionRegister.NEXT_HOP.getCode();

	private static final byte REG_MAC_KEY = 0x20;
	private static final byte REG_PAYLOAD_MAC = 0x21;
	private static final byte REG_SHARED_SECRET_MAC = 0x22;
	private static final byte REG_EXP_MAC_PAYLOAD = 0x23;
	private static final byte REG_STREAM_KEY = 0x24;
	private static final byte REG_KEYSTREAM = 0x25;
	private static final byte REG_PAYLOAD_COPY = 0x26;
	private static final byte REG_NEXT_HOPS_LENGTH = 0x27;
	private static final byte REG_PAYLOADLENGTH = 0x29;
	private static final byte REG_HEADER = 0x2A;
	private static final byte REG_TEMP_PAYLOAD = 0x2B;
	private static final byte REG_AlPHALENGTH = 0x30;
	private static final byte REG_BETALENGTH = 0x31;
	private static final byte REG_GAMMALENGTH = 0x32;


	public static byte[] createInstructionsSolo(byte[] nextHop, byte saltDec, byte[] payloadMAC, byte saltMAC)
			throws IOException {
		ByteArrayOutputStream instr = new ByteArrayOutputStream();

		// MAC verifizieren über Payload
		instr.write(Instruction.load(payloadMAC, REG_PAYLOAD_MAC));
		instr.write(Instruction.concateWithByteValue(REG_SHARED_SECRET, saltMAC, REG_SHARED_SECRET_MAC));
		instr.write(Instruction.hash(REG_SHARED_SECRET_MAC, REG_MAC_KEY));
		instr.write(Instruction.mac(REG_MAC_KEY, REG_PAYLOAD, REG_EXP_MAC_PAYLOAD));
		instr.write(Instruction.verify(REG_PAYLOAD_MAC, REG_EXP_MAC_PAYLOAD));

		// Payload entschlüsseln
		instr.write(Instruction.concateWithByteValue(REG_SHARED_SECRET, saltDec, REG_SHARED_SECRET));
		instr.write(Instruction.hash(REG_SHARED_SECRET, REG_STREAM_KEY));
		instr.write(Instruction.prgGenerate(REG_STREAM_KEY, REG_PAYLOAD, REG_KEYSTREAM));
		instr.write(Instruction.xor(REG_KEYSTREAM, REG_PAYLOAD, REG_PAYLOAD));

		// Mixen

		instr.write(Instruction.load(nextHop, REG_NEXT_HOP));
		instr.write(Instruction.forward(REG_NEXT_HOP));

		instr.write(Instruction.stop());
		return instr.toByteArray();
	}

	public static byte[] createInstructionsMulti(byte[] nextHopsLength, byte saltDec, byte[] payloadMAC, byte saltMAC,
			byte p, byte[] payloadLength, byte[] alphaLen, byte[] betaLen, byte[] gammaLen) throws IOException {
		ByteArrayOutputStream instr = new ByteArrayOutputStream();

		// MAC verifizieren über Payload
		instr.write(Instruction.load(payloadMAC, REG_PAYLOAD_MAC));
		instr.write(Instruction.concateWithByteValue(REG_SHARED_SECRET, saltMAC, REG_SHARED_SECRET_MAC));
		instr.write(Instruction.hash(REG_SHARED_SECRET_MAC, REG_MAC_KEY));
		instr.write(Instruction.mac(REG_MAC_KEY, REG_PAYLOAD, REG_EXP_MAC_PAYLOAD));
		instr.write(Instruction.verify(REG_PAYLOAD_MAC, REG_EXP_MAC_PAYLOAD));

		// Payload entschlüsseln
		instr.write(Instruction.concateWithByteValue(REG_SHARED_SECRET, saltDec, REG_SHARED_SECRET));
		instr.write(Instruction.hash(REG_SHARED_SECRET, REG_STREAM_KEY));
		instr.write(Instruction.prgGenerate(REG_STREAM_KEY, REG_PAYLOAD, REG_KEYSTREAM));
		instr.write(Instruction.xor(REG_KEYSTREAM, REG_PAYLOAD, REG_PAYLOAD));

		instr.write(Instruction.load(payloadLength, REG_PAYLOADLENGTH));
		instr.write(Instruction.load(alphaLen, REG_AlPHALENGTH));
		instr.write(Instruction.load(betaLen, REG_BETALENGTH));
		instr.write(Instruction.load(gammaLen, REG_GAMMALENGTH));
		instr.write(Instruction.load(nextHopsLength, REG_NEXT_HOPS_LENGTH));
		instr.write(Instruction.copy(REG_PAYLOAD, REG_PAYLOAD_COPY));

		// Jedes einzelnes unterpacket extrahieren und senden
		instr.write(Instruction.forLoop(p, (byte) 4));
		instr.write(Instruction.storeMultipleBytes(REG_PAYLOAD_COPY, REG_AlPHALENGTH, REG_ALPHA));
		instr.write(Instruction.storeMultipleBytes(REG_PAYLOAD_COPY, REG_BETALENGTH, REG_BETA));
		instr.write(Instruction.storeMultipleBytes(REG_PAYLOAD_COPY, REG_GAMMALENGTH, REG_GAMMA));
		instr.write(Instruction.storeMultipleBytes(REG_PAYLOAD_COPY, REG_PAYLOADLENGTH, REG_TEMP_PAYLOAD));
		instr.write(Instruction.storeMultipleBytes(REG_PAYLOAD_COPY, REG_NEXT_HOPS_LENGTH, REG_NEXT_HOP));

		// Mixen

		instr.write(Instruction.forward(REG_NEXT_HOP));

		instr.write(Instruction.stop());
		return instr.toByteArray();
	}
}
