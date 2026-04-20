package OmniSphinx;


import OmniSphinx.crypto.ECCGroup;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP224R1Curve;

import java.math.BigInteger;

import static OmniSphinx.SerializationUtils.concatenate;
import static OmniSphinx.SerializationUtils.slice;

public class Params {
    public static final byte HB_SALT = 0x00;
    public static final byte HRHO_SALT = 0x01;
    public static final byte HMU_SALT = 0x02;
    public static final byte HPI_SALT = 0x03;
    public static final byte HTAU_SALT = 0x04;

    private final int keyLength;
    private final int bodyLength;
    private final int headerLength;
    private final ECCGroup group;
    private int instructionTotalSize;

    public Params(int keyLength, int bodyLength, int headerLength, ECCGroup group, int instructionTotalSize) {
        this.keyLength = keyLength;
        this.bodyLength = bodyLength;
        this.headerLength = headerLength;
        this.group = group;
        this.instructionTotalSize = instructionTotalSize;
    }

    public Params() {
        this(16, 21410, 19200, new ECCGroup(), 5000);
    }

    public int keyLength() {
        return keyLength;
    }

    public int bodyLength() {
        return bodyLength;
    }

    public int headerLength() {
        return headerLength;
    }

    public int packetLength() {
        return headerLength + bodyLength;
    }

    public ECCGroup getGroup() {
        return group;
    }

    public void setInstructionTotalSize(int newInstructionTotalSize) {
        instructionTotalSize = newInstructionTotalSize;
    }

    public BigInteger generatePrivateKey() {
        return group.genSecret();
    }

    public ECPoint derivePublicKey(BigInteger privateKey) {
        return group.expon(group.getGenerator(), privateKey);
    }

    public byte[] aesCtr(byte[] key, byte[] message, byte[] iv) {
        CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
        SICBlockCipher engine = new SICBlockCipher(new AESEngine());

        engine.init(true, params);

        byte[] ciphertext = new byte[message.length];

        engine.processBytes(message, 0, message.length, ciphertext, 0);

        return ciphertext;
    }

    public int getInstructionTotalSize() {
        return instructionTotalSize;
    }

    public byte[] aesCtr(byte[] key, byte[] message) {
        byte[] iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        return aesCtr(key, message, iv);
    }


    public byte[] xorRho(byte[] key, byte[] plain) throws OmniSphinxException {
        if (key.length != keyLength) {
            throw new OmniSphinxException("Length of provided key (" + key.length + ") did not match the required key length (" + keyLength + ")");
        }

        return aesCtr(key, plain);
    }

    public byte[] lionessEnc(byte[] key, byte[] message) throws OmniSphinxException {
        if (key.length != keyLength) {
            throw new OmniSphinxException("Length of provided key (" + key.length + ") did not match the required key length (" + keyLength + ")");
        }

        if (message.length < keyLength * 2) {
            throw new OmniSphinxException("Length of provided message (" + message.length + ") needs to be at least double the length of the key (" + keyLength + ")");
        }

        // Round 1
        byte[] messageShort = slice(message, keyLength);
        byte[] messageLong = slice(message, keyLength, message.length);
        byte[] one = "1".getBytes();
        byte[] k1 = slice(hash(concatenate(messageLong, key, one)), keyLength);
        byte[] c = aesCtr(key, messageShort, k1);
        byte[] r1 = concatenate(c, messageLong);

        // Round 2
        byte[] r1Short = slice(r1, keyLength);
        byte[] r1Long = slice(r1, keyLength, message.length);
        c = aesCtr(key, r1Long, r1Short);
        byte[] r2 = concatenate(r1Short, c);

        // Round 3
        byte[] r2Short = slice(r2, keyLength);
        byte[] r2Long = slice(r2, keyLength, message.length);
        byte[] three = "3".getBytes();
        byte[] k3 = slice(hash(concatenate(r2Long, key, three)), keyLength);
        c = aesCtr(key, r2Short, k3);
        byte[] r3 = concatenate(c, r2Long);

        // Round 4
        byte[] r3Short = slice(r3, keyLength);
        byte[] r3Long = slice(r3, keyLength, message.length);
        c = aesCtr(key, r3Long, r3Short);
        byte[] r4 = concatenate(r3Short, c);

        return r4;
    }

    public byte[] lionessDec(byte[] key, byte[] message) throws OmniSphinxException {
        if (key.length != keyLength) {
            throw new OmniSphinxException("Length of provided key (" + key.length + ") did not match the required key length (" + keyLength + ")");
        }

        if (message.length < keyLength * 2) {
            throw new OmniSphinxException("Length of provided message (" + message.length + ") needs to be at least double the length of the key (" + keyLength + ")");
        }

        byte[] r4Short = slice(message, keyLength);
        byte[] r4Long = slice(message, keyLength, message.length);

        // Round 4
        byte[] r3Long = aesCtr(key, r4Long, r4Short);
        byte[] r3Short = r4Short;

        // Round 3
        byte[] three = "3".getBytes();
        byte[] k2 = slice(hash(concatenate(r3Long, key, three)), keyLength);
        byte[] r2Short = aesCtr(key, r3Short, k2);
        byte[] r2Long = r3Long;

        // Round 2
        byte[] r1Long = aesCtr(key, r2Long, r2Short);
        byte[] r1Short = r2Short;

        // Round 1
        byte[] one = "1".getBytes();
        byte[] k0 = slice(hash(concatenate(r1Long, key, one)), keyLength);
        byte[] c = aesCtr(key, r1Short, k0);
        byte[] r0 = concatenate(c, r1Long);

        return r0;
    }

    public byte[] encrypt(byte[] key, byte[] plaintext) throws OmniSphinxException {
        return lionessEnc(key, plaintext);
        //return aesCtr(key, plaintext);
    }

    public byte[] decrypt(byte[] key, byte[] ciphertext) throws OmniSphinxException {
        return lionessDec(key, ciphertext);
        //return aesCtr(key, ciphertext);
    }

    public byte[] prg(byte[] key) {
        return prg(key, 1024);
    }

    public byte[] prg(byte[] key, int outputLength) {
        byte[] iv = new byte[16];
        byte[] zeroInput = new byte[outputLength];
        return aesCtr(key, zeroInput, iv);
    }

    public byte[] computeSharedSecret(BigInteger priv, byte[] pubKey) {
        ECCurve curve = new SecP224R1Curve();
        ECPoint pub = curve.decodePoint(pubKey);
        ECPoint secret = pub.multiply(priv);
        return secret.getEncoded(false);
    }

    public byte[] exponent(byte[] base, byte[] exponent) {
        ECCurve curve = new SecP224R1Curve();
        ECPoint basePoint = curve.decodePoint(base);
        BigInteger exp = new BigInteger(1, exponent);
        ECPoint result = basePoint.multiply(exp);
        return result.getEncoded(false);
    }

    public byte[] mac(byte[] key, byte[] data) {
        Mac mac = new HMac(new SHA256Digest());
        CipherParameters cipherParameters = new KeyParameter(key);
        mac.init(cipherParameters);
        byte[] output = new byte[mac.getMacSize()];

        mac.update(data, 0, data.length);
        mac.doFinal(output, 0);

        return slice(output, keyLength);
    }

    public byte[] hash(byte[] data) {
        SHA256Digest digest = new SHA256Digest();
        byte[] output = new byte[digest.getDigestSize()];

        digest.update(data, 0, data.length);
        digest.doFinal(output, 0);

        return slice(output, keyLength);
    }

    public byte[] getAesKey(ECPoint s) {
        byte[] prefix = "aes_key:".getBytes();
        byte[] printable = group.printable(s);

        byte[] data = concatenate(prefix, printable);
        byte[] hash = hash(data);

        return slice(hash, keyLength);
    }

    public byte[] deriveKey(byte[] k, byte flavor) {
        byte[] data = concatenate(k, flavor);
        return hash(data);
    }

    public BigInteger hb(ECPoint alpha, byte[] k) {
        byte[] K = deriveKey(k, HB_SALT);

        return group.makeexp(K);
    }

    public byte[] hrho(byte[] k) {
        byte flavor = HRHO_SALT;

        return deriveKey(k, flavor);
    }

    public byte[] hmu(byte[] k) {
        byte flavor = HMU_SALT;

        return deriveKey(k, flavor);
    }

    public byte[] hpi(byte[] k) {
        byte flavor = HPI_SALT;

        return deriveKey(k, flavor);
    }

    public byte[] htau(byte[] k) {
        byte flavor = HTAU_SALT;

        return deriveKey(k, flavor);
    }
}
