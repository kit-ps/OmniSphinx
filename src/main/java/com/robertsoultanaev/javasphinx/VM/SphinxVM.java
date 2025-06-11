package com.robertsoultanaev.javasphinx.VM;

import com.robertsoultanaev.javasphinx.SerializationUtils;
import com.robertsoultanaev.javasphinx.SphinxException;
import com.robertsoultanaev.javasphinx.SphinxParams;
import com.robertsoultanaev.javasphinx.VM.VMException;
import com.robertsoultanaev.javasphinx.crypto.ECCGroup;
import com.robertsoultanaev.javasphinx.packet.ProcessedPacket;
import com.robertsoultanaev.javasphinx.packet.SphinxPacket;
import com.robertsoultanaev.javasphinx.packet.instruction.OpCode;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP224R1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static com.robertsoultanaev.javasphinx.SerializationUtils.concatenate;
import static com.robertsoultanaev.javasphinx.SerializationUtils.slice;


public class SphinxVM {
    private SphinxPacket RecievedPacket;
    private ProcessedPacket processedPacket;
    private BigInteger nodeSecret;
    private byte[][] registers = new byte[256][64];
    private byte[] rawpacket;
    private byte[] aesS;
    private SphinxParams params;
    private byte[] hmu;

    public SphinxVM(BigInteger nodeSecret, SphinxParams params) {
        this.nodeSecret = nodeSecret;
        this.params = params;
    }

    public ProcessedPacket interpret(byte[] Rawpacket, byte[] instructions, SphinxPacket packet) throws VMException {
        RecievedPacket = packet;
        rawpacket = Rawpacket.clone();
        interpretInstructions(instructions);
        return processedPacket;
    }

    private void interpretInstructions(byte[] instructions) throws VMException {
        for (int pc = 0; pc < instructions.length;) {
            OpCode opcode = OpCode.fromByte(instructions[pc++]);
            try {
                switch (opcode) {
                    case STORE -> {
                        byte value = instructions[pc++];
                        byte destReg = instructions[pc++];
                        store(value, destReg);
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
                        byte groupId = instructions[pc++];
                        computeSharedSecret(pubKeyReg, destReg, groupId);
                    }
                    case HASH -> {
                        byte hashType = instructions[pc++];
                        byte inputReg = instructions[pc++];
                        byte destReg = instructions[pc++];
                        hash(hashType, inputReg, destReg);
                    }
                    case MAC -> {
                        byte keyReg = instructions[pc++];
                        byte dataReg = instructions[pc++];
                        byte macType = instructions[pc++];
                        byte destReg = instructions[pc++];
                        mac(keyReg, dataReg, macType, destReg);
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
                        byte group = instructions[pc++];
                        byte outputLen = instructions[pc++];
                        exponent(reg1, reg2, destReg, group, outputLen);
                    }
                    case PAD -> {
                        byte padReg = instructions[pc++];
                        byte length = instructions[pc++];
                        byte destReg = instructions[pc++];
                        pad(padReg, length, destReg);
                    }
                    case PRG_GENERATE -> {
                        byte seedReg = instructions[pc++];
                        byte hashType = instructions[pc++];
                        byte destReg = instructions[pc++];
                        prgGenerate(seedReg, hashType, destReg);
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
                        byte hashType = instructions[pc++];
                        byte destReg = instructions[pc++];
                        decrypt(keyReg, inputReg, hashType, destReg);
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
                    default -> throw new VMException("Unknown OpCode: " + opcode);
                }
            } catch (VMException e) {
                throw new VMException("Error at instruction " + opcode + ": " + e.getMessage(), e);
            }
        }
    }

    private void store(byte value, byte destReg) throws VMException {
        Arrays.fill(registers[destReg], value);
    }


    private void storeBytes(byte source, byte length, byte destReg) throws VMException {
        int startByte = 0;
        int lengthBytes = Byte.toUnsignedInt(length);


        byte[] src;
        if(source == 0x00) {
            src = rawpacket;
        } else {
            src = registers[source];
        }


        if (startByte + lengthBytes > src.length) {
            throw new VMException("storeByte out of bounds");
        }

        byte[] extracted = Arrays.copyOfRange(src, startByte, startByte + lengthBytes);
        registers[destReg] = extracted;

        // Entferne aus source
        byte[] newSrc = new byte[src.length - lengthBytes];
        System.arraycopy(src, 0, newSrc, 0, startByte);
        System.arraycopy(src, startByte + lengthBytes, newSrc, startByte, src.length - (startByte + lengthBytes));
        if(source == 0x00) {
            rawpacket = newSrc;
        } else {
            registers[source] = newSrc;
        }
    }

    private void computeSharedSecret(byte pubKeyReg, byte destReg, byte groupId) throws VMException {
        try {
            byte[] pubKeyBytes = registers[pubKeyReg];
            byte[] result;

            switch (groupId) {
                case 0x00 -> {
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


                    result = s.getEncoded(false);
                }
                case 0x01 -> {
                    // klassische DH-Gruppe (mod p)
                    BigInteger base = new BigInteger(1, pubKeyBytes);
                    BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1", 16);
                    BigInteger secret = base.modPow(nodeSecret, p);
                    result = secret.toByteArray();
                }

                case 0x02 -> {
                    // EC-Gruppe: secp256r1
                    ECCurve curve = new SecP256R1Curve();
                    ECPoint pubPoint = curve.decodePoint(pubKeyBytes);
                    ECPoint secretPoint = pubPoint.multiply(nodeSecret);
                    result = secretPoint.getEncoded(false); // uncompressed
                }
                default -> throw new VMException("Unsupported groupId in computeSharedSecret: " + groupId);
            }

            registers[destReg] = result;

        } catch (Exception e) {
            throw new VMException("Shared secret computation failed: " + e.getMessage(), e);
        }
    }



    private void hash(byte hashType, byte inputReg, byte destReg) throws VMException {
        try {
            byte[] input = registers[inputReg];

            switch (hashType) {
                // Klassische Hashes
                case 0x01: // SHA-256
                case 0x02: // SHA-1
                case 0x03: // SHA-512 -
                    String algo = switch (hashType) {
                        case 0x01 -> "SHA-256";
                        case 0x02 -> "SHA-1";
                        case 0x03 -> "SHA-512";
                        default -> throw new VMException("Invalid classic hash type");
                    };
                    MessageDigest digest = MessageDigest.getInstance(algo);
                    registers[destReg] = digest.digest(input);
                    break;

                // AES-CTR basierte "Flavour-Hashes"
                case 0x10: // hmu
                case 0x11: // hrho
                case 0x12: // hpi
                case 0x13: // htau
                    //TODO Richtig implementieren undzwar variabel!
                    byte[] iv = getFlavorIV(hashType);
                    byte[] m = new byte[16]; // zero input
                    registers[destReg] = aesCtr(input, m, iv);
                    break;
                case 0x14: // aes_key
                    //TODO Richtig implementieren undzwar Variabel!
                    byte[] prefix = getFlavorIV(hashType);
                    byte[] data = concate(prefix, registers[inputReg]);
                    SHA256Digest SHA256Digest = new SHA256Digest();
                    byte[] output = new byte[SHA256Digest.getDigestSize()];

                    SHA256Digest.update(data, 0, data.length);
                    SHA256Digest.doFinal(output, 0);
                    registers[destReg] = slice(output, 16);
                    aesS = registers[destReg];
                    break;
                case 0x15:  //hb
                    //TODO Richtig implementieren
                    iv = getFlavorIV(hashType);
                    m = new byte[16]; // zero input
                    registers[destReg] = aesCtr(input, m, iv);
                    break;
                default:
                    throw new VMException("Unsupported hash type: " + hashType);
            }
        } catch (Exception e) {
            throw new VMException("Hash failed: " + e.getMessage(), e);
        }
    }

    private void mac(byte keyReg, byte dataReg, byte hashType, byte destReg) throws VMException {
        switch(hashType) {
            case 0x01 -> {
                try {
                    Mac mac = new HMac(new SHA256Digest());
                    CipherParameters cipherParameters = new KeyParameter(registers[keyReg]);
                    mac.init(cipherParameters);
                    byte[] output = new byte[mac.getMacSize()];

                    mac.update(registers[dataReg], 0, registers[dataReg].length);
                    mac.doFinal(output, 0);


                    //TODO KeyLength variabel!
                    int keyLength = 16; // oder dynamisch aus params lesen
                    registers[destReg] = slice(output, keyLength);



                } catch (Exception e) {
                    throw new VMException("MAC failed: " + e.getMessage(), e);
                }
            }
            default -> {
                throw new VMException("MAC noch nicht implementiert");
            }
        }

    }

    private void verify(byte expectedReg, byte computedReg) throws VMException {
        //if(!Arrays.equals(RecievedPacket.packetContent().header().getGamma(), registers[expectedReg])) {
          //  throw new VMException("Irgendwas stimmt mit Gamma nicht?!");
        //}
        if (!Arrays.equals(registers[expectedReg], registers[computedReg])) {
            throw new VMException("MAC verification failed");
        }
        System.out.println("Verify hat funktioniert!");
    }

    private void exponent(byte baseReg, byte expReg, byte destReg, byte groupId, byte outputLength) throws VMException {
        try {
            byte[] alpha = registers[baseReg];
            byte[] result;

            switch (groupId) {
                case 0x00 -> {
                    // EC-Gruppe: secp224r1
                    ECCurve curve = new SecP224R1Curve();
                    ECPoint pubPoint = curve.decodePoint(alpha);
                    ECPoint s = pubPoint.multiply(nodeSecret);
                    result = s.getEncoded(false);
                }
                case 0x01 -> {
                    // klassische DH-Gruppe (mod p)
                    BigInteger base = new BigInteger(1, alpha);
                    BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1", 16);
                    BigInteger secret = base.modPow(nodeSecret, p);
                    result = secret.toByteArray();
                }

                case 0x02 -> {
                    // EC-Gruppe: secp256r1
                    ECCurve curve = new SecP256R1Curve();
                    ECPoint pubPoint = curve.decodePoint(alpha);
                    ECPoint secretPoint = pubPoint.multiply(nodeSecret);
                    result = secretPoint.getEncoded(false); // uncompressed
                }
                default -> throw new VMException("Unsupported groupId in computeSharedSecret: " + groupId);
            }

            registers[destReg] = result;

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
        System.out.println(registers[destReg].length);
    }


    private void prgGenerate(byte seedReg, byte type, byte destReg) throws VMException {
        switch(type) {
            case 0x01 -> {
                try{
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] result = digest.digest(registers[seedReg]);
                    System.arraycopy(result, 0, registers[destReg], 0, Math.min(result.length, registers[destReg].length));
                } catch (NoSuchAlgorithmException e) {
                    throw new VMException("PRG failed: " + e.getMessage());
                }
            }
            case 0x02 -> {
                try {
                    MessageDigest digest = MessageDigest.getInstance("SHA-1");
                    byte[] result = digest.digest(registers[seedReg]);
                    System.arraycopy(result, 0, registers[destReg], 0, Math.min(result.length, registers[destReg].length));
                } catch (NoSuchAlgorithmException e) {
                    throw new VMException("PRG failed: " + e.getMessage());
                }

            }
            case 0x03 -> {
                byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
                //TODO Variabele länge!
                System.out.println(registers[seedReg].length);
                try {
                    registers[destReg] = aesCtrKeystream(registers[seedReg], iv, 192);
                } catch (Exception e) {
                    throw new VMException("PRG Generate mit AESCTR Keystream hat nicht so geklappt?!");
                }
            }
            default -> throw new VMException("Unsupported PRG type: " + type);
        }
    }

    private void xor(byte inputA, byte inputB, byte destReg) throws VMException {
        byte[] a = registers[inputA];
        byte[] b = registers[inputB];

        if (a.length != b.length) {
            throw new VMException("XOR: Register lengths do not match");
        }

        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        registers[destReg] = result;
    }

    private void decrypt(byte keyReg, byte inputReg, byte algoType, byte destReg) throws VMException {
        switch(algoType) {
            case 0x01 -> {
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
            case 0x02 -> {
                try {
                    Cipher cipher = Cipher.getInstance("Blowfish");
                    SecretKeySpec key = new SecretKeySpec(registers[keyReg], cipher.getAlgorithm());
                    cipher.init(Cipher.DECRYPT_MODE, key);
                    byte[] result = cipher.doFinal(registers[inputReg]);
                    System.arraycopy(result, 0, registers[destReg], 0, Math.min(result.length, registers[destReg].length));
                } catch (Exception e) {
                    throw new VMException("Decrypt with Blowfish does not work");
                }

            }
            case 0x03 -> {
                int keyLength = 16;
                try {
                    registers[destReg] = lionessDec(registers[keyReg], registers[inputReg], keyLength);
                } catch (Exception e) {
                    throw new VMException("Decrypt with lionessDec does not work");
                }
            }
            default -> {
                throw new VMException("Decryption Algo not implemented");
            }
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

    private byte[] concate(byte[] data1, byte[] data2) throws VMException {
        byte[] result = new byte[data1.length + data2.length];
        System.arraycopy(data1, 0, result, 0, data1.length);
        System.arraycopy(data2, 0, result, data1.length, data2.length);

        return result;
    }

    private void forward(byte idReg, byte payloadReg) throws VMException {
    }

    private byte[] aesCtrKeystream(byte[] key, byte[] iv, int length) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] zeroInput = new byte[length]; // enthält nur 0x00
        return aesCtr(key, zeroInput, iv);   // nutzt deine bestehende aesCtr
    }

    private byte[] aesCtr(byte[] key, byte[] message, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(message);
    }

    private byte[] getFlavorIV(byte hashType) throws VMException {
        return switch (hashType) {
            case 0x10 -> "hmu:hmu:hmu:hmu:".getBytes();
            case 0x11 -> "hrhohrhohrhohrho".getBytes();
            case 0x12 -> "hpi:hpi:hpi:hpi:".getBytes();
            case 0x13 -> "htauhtauhtauhtau".getBytes();
            case 0x14 -> "aes_key:".getBytes();
            case 0x15 -> "hbhbhbhbhbhbhbhb".getBytes();
            default -> throw new VMException("Unknown flavor IV type: " + hashType);
        };
    }

    private byte[] slice(byte[] source, int start, int end) {
        int resultLength = end - start;
        byte[] result = new byte[resultLength];
        System.arraycopy(source, start, result, 0, resultLength);
        return result;
    }

    private byte[] slice(byte[] source, int end) {
        return slice(source, 0, end);
    }

    private void lionessCheckLengths(byte[] key, byte[] message, int keyLength) throws SphinxException {
        if (key.length != keyLength) {
            throw new SphinxException("Length of provided key (" + key.length + ") did not match the required key length (" + keyLength + ")");
        }

        if (message.length < keyLength * 2) {
            throw new SphinxException("Length of provided message (" + message.length + ") needs to be at least double the length of the key (" + keyLength + ")");
        }
    }

    private byte[] lionessDec(byte[] key, byte[] message, int keyLength) throws SphinxException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        lionessCheckLengths(key, message, keyLength);

        byte[] r4Short = slice(message, keyLength);
        byte[] r4Long = slice(message, keyLength, message.length);

        // Round 4
        byte[] r3Long = aesCtr(key, r4Long, r4Short);

        // Round 3
        byte[] three = "3".getBytes();
        byte[] k2 = slice(hash(concatenate(r3Long, key, three)), keyLength);
        byte[] r2Short = aesCtr(key, r4Short, k2);

        // Round 2
        byte[] r1Long = aesCtr(key, r3Long, r2Short);

        // Round 1
        byte[] one = "1".getBytes();
        byte[] k0 = slice(hash(concatenate(r1Long, key, one)), keyLength);
        byte[] c = aesCtr(key, r2Short, k0);

        return concatenate(c, r1Long);
    }

    private byte[] hash(byte[] data) {
        SHA256Digest digest = new SHA256Digest();
        byte[] output = new byte[digest.getDigestSize()];

        digest.update(data, 0, data.length);
        digest.doFinal(output, 0);

        return output;
    }

    private static byte[] concatenate(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }

        byte[] result = new byte[length];

        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }

        return result;
    }
}

