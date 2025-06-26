package MasterThesisFormat.VM;

import javasphinx.SphinxParams;
import javasphinx.packet.ProcessedPacket;
import javasphinx.packet.SphinxPacket;
import MasterThesisFormat.instruction.OpCode;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP224R1Curve;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static MasterThesisFormat.VM.VMUtil.*;


public class SphinxVM {
    private SphinxPacket RecievedPacket;
    private ProcessedPacket processedPacket;
    private BigInteger nodeSecret;
    private byte[][] registers;
    private byte[] rawpacket;
    private SphinxParams params;

    public SphinxVM(BigInteger nodeSecret, SphinxParams params) {
        this.registers = new byte[256][64];
        this.nodeSecret = nodeSecret;
        this.params = params;
    }

    public ProcessedPacket interpret(byte[] Rawpacket, byte[] instructions, SphinxPacket packet) throws VMException {
        registers[0x00] = Rawpacket;
        RecievedPacket = packet;
        rawpacket = Rawpacket;
        interpretInstructions(instructions);
        return processedPacket;
    }

    private void interpretInstructions(byte[] instructions) throws VMException {
        for (int pc = 0; pc < instructions.length;) {
            OpCode opcode = OpCode.fromByte(instructions[pc++]);
            try {
                switch (opcode) {
                    case FOR -> {
                        int times = Byte.toUnsignedInt(instructions[pc++]);
                        int instrCount = Byte.toUnsignedInt(instructions[pc++]);

                        int programCounter = pc;
                        pc = executeFor(instructions, times, instrCount, programCounter);
                    }
                    case STORE_BYTES -> {
                        byte source = instructions[pc++];
                        byte length = instructions[pc++];
                        byte destReg = instructions[pc++];
                        storeBytes(source, length, destReg);
                    }
                    case COMPUTE_SHARED_SECRET -> {
                        byte pubKeyReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        computeSharedSecret(pubKeyReg, destReg);
                    }
                    case HASH -> {
                        byte inputReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        hash(inputReg, destReg);
                    }
                    case MAC -> {
                        byte keyReg = instructions[pc++];
                        byte dataReg = instructions[pc++];
                        byte length = instructions[pc++];
                        byte destReg = instructions[pc++];
                        mac(keyReg, dataReg, length, destReg);
                    }
                    case VERIFY -> {
                        byte expectedReg = instructions[pc++];
                        byte computedReg = instructions[pc++];
                        verify(expectedReg, computedReg);
                    }
                    case EXPONENT -> {
                        byte reg1 = instructions[pc++];
                        byte reg2 = instructions[pc++];
                        byte destReg = instructions[pc++];
                        byte outputLen = instructions[pc++];
                        exponent(reg1, reg2, destReg, outputLen);
                    }
                    case PAD -> {
                        byte padReg = instructions[pc++];
                        byte length = instructions[pc++];
                        byte destReg = instructions[pc++];
                        pad(padReg, length, destReg);
                    }
                    case PRG_GENERATE -> {
                        byte seedReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        prgGenerate(seedReg, destReg);
                    }
                    case XOR -> {
                        byte inputA = instructions[pc++];
                        byte inputB = instructions[pc++];
                        byte destReg = instructions[pc++];
                        xor(inputA, inputB, destReg);
                    }
                    case DECRYPT -> {
                        byte keyReg = instructions[pc++];
                        byte inputReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        decrypt(keyReg, inputReg, destReg);
                    }
                    case CONCATE -> {
                        byte reg1 = instructions[pc++];
                        byte reg2 = instructions[pc++];
                        byte destReg = instructions[pc++];
                        concate(reg1, reg2, destReg);
                    }
                    case FIND_NEXT -> {
                        byte sourceReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        findNext(sourceReg, destReg);
                    }
                    case FORWARD -> {
                        byte idReg = instructions[pc++];
                        byte payloadReg = instructions[pc++];
                        forward(idReg, payloadReg);
                    }
                    case ENCRYPT -> {
                        byte keyReg = instructions[pc++];
                        byte inputReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        encrypt(keyReg, inputReg, destReg);
                    }
                    case MIX_NONE -> {
                        // Direkt weiterleiten → keine Aktion nötig
                    }

                    case MIX_TIMED -> {
                        byte delay = instructions[pc++];
                        applyTimedMix(delay);
                    }

                    case MIX_THRESHOLD -> {
                        byte bufferSize = instructions[pc++];
                        applyThresholdMix(bufferSize);
                    }

                    case MIX_POOL -> {
                        byte poolSize = instructions[pc++];
                        byte outflowRate = instructions[pc++];
                        applyPoolMix(poolSize, outflowRate);
                    }

                    case MIX_POISSON -> {
                        byte meanDelay = instructions[pc++];
                        applyPoissonMix(meanDelay);
                    }
                    default -> throw new VMException("Unknown OpCode: " + opcode);
                }
            } catch (VMException e) {
                throw new VMException("Error at instruction " + opcode + ": " + e.getMessage(), e);
            }
        }
    }

    private int executeFor(byte[] instructions, int times, int instrCount, int programCounter) throws VMException {
        int blockEnd = programCounter;

        for (int i = 0; i < times; i++) {
            int innerPc = programCounter;

            for (int j = 0; j < instrCount; j++) {
                OpCode innerOpcode = OpCode.fromByte(instructions[innerPc++]);

                switch (innerOpcode) {
                    case STORE_BYTES -> {
                        byte source = instructions[innerPc++];
                        byte length = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        storeBytes(source, length, destReg);
                    }
                    case COMPUTE_SHARED_SECRET -> {
                        byte pubKeyReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        computeSharedSecret(pubKeyReg, destReg);
                    }
                    case HASH -> {
                        byte inputReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        hash(inputReg, destReg);
                    }
                    case MAC -> {
                        byte keyReg = instructions[innerPc++];
                        byte dataReg = instructions[innerPc++];
                        byte length = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        mac(keyReg, dataReg,length, destReg);
                    }
                    case VERIFY -> {
                        byte expectedReg = instructions[innerPc++];
                        byte computedReg = instructions[innerPc++];
                        verify(expectedReg, computedReg);
                    }
                    case EXPONENT -> {
                        byte reg1 = instructions[innerPc++];
                        byte reg2 = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        byte outputLen = instructions[innerPc++];
                        exponent(reg1, reg2, destReg, outputLen);
                    }
                    case PAD -> {
                        byte padReg = instructions[innerPc++];
                        byte length = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        pad(padReg, length, destReg);
                    }
                    case PRG_GENERATE -> {
                        byte seedReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        prgGenerate(seedReg, destReg);
                    }
                    case XOR -> {
                        byte inputA = instructions[innerPc++];
                        byte inputB = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        xor(inputA, inputB, destReg);
                    }
                    case DECRYPT -> {
                        byte keyReg = instructions[innerPc++];
                        byte inputReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        decrypt(keyReg, inputReg, destReg);
                    }
                    case CONCATE -> {
                        byte reg1 = instructions[innerPc++];
                        byte reg2 = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        concate(reg1, reg2, destReg);
                    }
                    case FIND_NEXT -> {
                        byte sourceReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        findNext(sourceReg, destReg);
                    }
                    case FORWARD -> {
                        byte idReg = instructions[innerPc++];
                        byte payloadReg = instructions[innerPc++];
                        forward(idReg, payloadReg);
                    }
                    case ENCRYPT -> {
                        byte keyReg = instructions[innerPc++];
                        byte inputReg = instructions[innerPc++];
                        byte destReg = instructions[innerPc++];
                        encrypt(keyReg, inputReg, destReg);
                    }
                    case MIX_NONE -> {
                        // Direkt weiterleiten → keine Aktion nötig
                    }

                    case MIX_TIMED -> {
                        byte delay = instructions[innerPc++];
                        applyTimedMix(delay);
                    }

                    case MIX_THRESHOLD -> {
                        byte bufferSize = instructions[innerPc++];
                        applyThresholdMix(bufferSize);
                    }

                    case MIX_POOL -> {
                        byte poolSize = instructions[innerPc++];
                        byte outflowRate = instructions[innerPc++];
                        applyPoolMix(poolSize, outflowRate);
                    }

                    case MIX_POISSON -> {
                        byte meanDelay = instructions[innerPc++];
                        applyPoissonMix(meanDelay);
                    }
                    default -> throw new VMException("Unknown OpCode in FOR block: " + innerOpcode);
                }
            }
            blockEnd = innerPc;
        }
        return blockEnd;
    }


    private void storeBytes(byte source, byte length, byte destReg) throws VMException {
        int startByte = 0;
        int lengthBytes = Byte.toUnsignedInt(length);

        byte[] src = registers[source];


        if (startByte + lengthBytes > src.length) {
            throw new VMException("storeByte out of bounds");
        }

        byte[] extracted = Arrays.copyOfRange(src, startByte, startByte + lengthBytes);
        registers[destReg] = extracted;

        // Entferne aus source
        byte[] newSrc = new byte[src.length - lengthBytes];
        System.arraycopy(src, 0, newSrc, 0, startByte);
        System.arraycopy(src, startByte + lengthBytes, newSrc, startByte, src.length - (startByte + lengthBytes));
        registers[source] = newSrc;
    }

    private void computeSharedSecret(byte pubKeyReg, byte destReg) throws VMException {
        try {
            byte[] pubKeyBytes = registers[pubKeyReg];

            // EC-Gruppe: secp224r1
            ECCurve curve = new SecP224R1Curve();
            ECPoint pubPoint = curve.decodePoint(pubKeyBytes);
            ECPoint s = pubPoint.multiply(nodeSecret);

            //Debug Code damit alles richtig ist!
            if(!pubPoint.equals(RecievedPacket.packetContent().header().alpha())) {
                throw new VMException("computeSharedSecret kaputt 2!");
            }
            if(!s.equals(RecievedPacket.packetContent().header().alpha().multiply(nodeSecret))) {
                throw new VMException("computeSharedSecret kaputt 2!");
            }
            byte[] result = s.getEncoded(false);
            registers[destReg] = result;

        } catch (Exception e) {
            throw new VMException("Shared secret computation failed: " + e.getMessage(), e);
        }
    }



    private void hash(byte inputReg, byte destReg) throws VMException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] input = registers[inputReg];
            byte[] result = digest.digest(input);
            System.arraycopy(result, 0, registers[destReg], 0, result.length);
        } catch (NoSuchAlgorithmException e) {
            throw new VMException("SHA-512 not available");
        }
    }

    private void mac(byte keyReg, byte dataReg, byte length, byte destReg) throws VMException {
        try {
            Mac mac = new HMac(new SHA256Digest());
            CipherParameters cipherParameters = new KeyParameter(registers[keyReg]);
            mac.init(cipherParameters);
            byte[] output = new byte[mac.getMacSize()];

            mac.update(registers[dataReg], 0, registers[dataReg].length);
            mac.doFinal(output, 0);

            registers[destReg] = slice(output, length);
        } catch (Exception e) {
            throw new VMException("MAC funkt nicht!");
        }
    }

    private void verify(byte expectedReg, byte computedReg) throws VMException {
        if (!Arrays.equals(registers[expectedReg], registers[computedReg])) {
            throw new VMException("MAC verification failed");
        }
    }

    private void exponent(byte baseReg, byte expReg, byte destReg, byte outputLength) throws VMException {
        try {
            // EC-Gruppe: secp224r1
            ECCurve curve = new SecP224R1Curve();
            ECPoint pubPoint = curve.decodePoint(registers[baseReg]);
            BigInteger scalar = new BigInteger(1, registers[expReg]);
            ECPoint result = pubPoint.multiply(scalar);
            registers[destReg] = result.getEncoded(false);
        } catch (Exception e) {
            throw new VMException("exponend failed: " + e.getMessage(), e);
        }
    }

    private void pad(byte inputReg, byte targetLength, byte destReg) throws VMException {
        int len = Byte.toUnsignedInt(targetLength);
        byte[] input = registers[inputReg];

        if (len > registers[destReg].length) {
            throw new VMException("Target length exceeds destination register size.");
        }

        byte[] output = new byte[registers[destReg].length + len];
        Arrays.fill(output, (byte) 0x00);

        System.arraycopy(input, 0, output, 0, input.length);

        registers[destReg] = output;
    }


    private void prgGenerate(byte seedReg, byte destReg) throws VMException {
        byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        try {
            registers[destReg] = aesCtrKeystream(registers[seedReg], iv);
        } catch (Exception e) {
            throw new VMException("PRG Generate mit AESCTR Keystream hat nicht so geklappt?!");
        }
    }


    private void xor(byte inputA, byte inputB, byte destReg) throws VMException {
        byte[] a = registers[inputA];
        byte[] b = registers[inputB];

        byte[] result;
        if (a.length < b.length) {
            result = new byte[a.length];
        } else {
            result = new byte[b.length];
        }

        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        registers[destReg] = result;
    }

    private void decrypt(byte keyReg, byte inputReg, byte destReg) throws VMException {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec key = new SecretKeySpec(registers[keyReg], cipher.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] result = cipher.doFinal(registers[inputReg]);
            System.arraycopy(result, 0, registers[destReg], 0, Math.min(result.length, registers[destReg].length));
        } catch(Exception e) {
            throw new VMException("Decrypt with AES ECB does not work");
        }
    }

    private void encrypt(byte keyReg, byte inputReg, byte destReg) throws VMException {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec key = new SecretKeySpec(registers[keyReg], cipher.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] result = cipher.doFinal(registers[inputReg]);
            System.arraycopy(result, 0, registers[destReg], 0, Math.min(result.length, registers[destReg].length));
        } catch (Exception e) {
            throw new VMException("Encrypt with AES ECB does not work");
        }
    }

    private void findNext(byte sourceReg, byte destReg) throws VMException {
        byte[] src = registers[sourceReg];

        if (src.length < 1) {
            throw new VMException("findNext: source too short");
        }

        int len = Byte.toUnsignedInt(src[0]); // erstes Byte gibt Länge an
        if (src.length < 1 + len) {
            throw new VMException("findNext: insufficient bytes for routing info");
        }

        // Extrahiere Routing-Info
        byte[] routing = Arrays.copyOfRange(src, 1, 1 + len);
        registers[destReg] = routing;

        // Entferne die genutzten Bytes aus source
        byte[] remainder = Arrays.copyOfRange(src, 1 + len, src.length);
        registers[sourceReg] = remainder;
    }

    private void concate(byte reg1, byte reg2, byte destReg) throws VMException {
        byte[] data1 = registers[reg1];
        byte[] data2 = registers[reg2];

        byte[] result = new byte[data1.length + data2.length];
        System.arraycopy(data1, 0, result, 0, data1.length);
        System.arraycopy(data2, 0, result, data1.length, data2.length);

        registers[destReg] = result;
    }


    private void forward(byte idReg, byte payloadReg) throws VMException {
    }

    private void applyTimedMix(byte delay) throws VMException {
        try {
            Thread.sleep(Byte.toUnsignedInt(delay));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VMException("Timed mix interrupted");
        }
    }

    private void applyPoissonMix(byte meanDelay) throws VMException {
        double mean = Byte.toUnsignedInt(meanDelay);
        double sampled = -mean * Math.log(1.0 - Math.random());
        try {
            Thread.sleep((long) sampled);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VMException("Poisson mix interrupted");
        }
    }

    private void applyThresholdMix(byte bufferSize) throws VMException {
        throw new VMException("Threshold mix not implemented yet: Buffer size = " + bufferSize);
    }

    private void applyPoolMix(byte poolSize, byte outflowRate) throws VMException {
        throw new VMException("Pool mix not implemented yet: PoolSize = " + poolSize + ", Outflow = " + outflowRate);
    }
}

