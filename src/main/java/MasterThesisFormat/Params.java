package MasterThesisFormat;


import MasterThesisFormat.crypto.ECCGroup;
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

import static MasterThesisFormat.SerializationUtils.concatenate;
import static MasterThesisFormat.SerializationUtils.slice;

public class Params {
    private final int keyLength;
    private final int bodyLength;
    private final int headerLength;
    private final ECCGroup group;
    private final int instructionTotalSize = 512;

    public Params(int keyLength, int bodyLength, int headerLength, ECCGroup group) {
        this.keyLength = keyLength;
        this.bodyLength = bodyLength;
        this.headerLength = headerLength;
        this.group = group;
    }

    public Params() {
        this(16, 1024, 192, new ECCGroup());
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

    public void lionessCheckLengths(byte[] key, byte[] message) throws OmniSphinxException {
        if (key.length != keyLength) {
            throw new OmniSphinxException("Length of provided key (" + key.length + ") did not match the required key length (" + keyLength + ")");
        }

        if (message.length < keyLength * 2) {
            throw new OmniSphinxException("Length of provided message (" + message.length + ") needs to be at least double the length of the key (" + keyLength + ")");
        }
    }

    public byte[] lionessEnc(byte[] key, byte[] message) throws OmniSphinxException {
        lionessCheckLengths(key, message);

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

        return concatenate(r3Short, c);
    }

    public byte[] lionessDec(byte[] key, byte[] message) throws OmniSphinxException {
        lionessCheckLengths(key, message);

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

    public byte[] xorRho(byte[] key, byte[] plain) throws OmniSphinxException {
        if (key.length != keyLength) {
            throw new OmniSphinxException("Length of provided key (" + key.length + ") did not match the required key length (" + keyLength + ")");
        }

        return aesCtr(key, plain);
    }

    public byte[] mu(byte[] key, byte[] data) {
        Mac mac = new HMac(new SHA256Digest());
        CipherParameters cipherParameters = new KeyParameter(key);
        mac.init(cipherParameters);
        byte[] output = new byte[mac.getMacSize()];

        mac.update(data, 0, data.length);
        mac.doFinal(output, 0);

        return slice(output, keyLength);
    }

    public byte[] pi(byte[] key, byte[] data) throws OmniSphinxException {
        if (key.length != keyLength) {
            throw new OmniSphinxException("Length of provided key (" + key.length + ") did not match the required key length (" + keyLength + ")");
        }

        if (data.length != bodyLength) {
            throw new OmniSphinxException("Length of provided message (" + data.length + ") did not match the required message body length (" + bodyLength + ")");
        }

        return lionessEnc(key, data);
    }

    public byte[] pii(byte[] key, byte[] data) throws OmniSphinxException {

        if (key.length != keyLength) {
            throw new OmniSphinxException("Length of provided key (" + key.length + ") did not match the required key length (" + keyLength + ")");
        }

        if (data.length != bodyLength) {
            throw new OmniSphinxException("Length of provided message (" + data.length + ") did not match the required message body length (" + bodyLength + ")");
        }
        return lionessDec(key, data);
    }

    public byte[] encrypt(byte[] key, byte[] plaintext) {
        byte[] iv = new byte[16]; // 16 null bytes as IV (CTR mode requirement)
        StreamCipher cipher = new SICBlockCipher(new AESFastEngine());
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] ciphertext = new byte[plaintext.length];
        cipher.processBytes(plaintext, 0, plaintext.length, ciphertext, 0);
        return ciphertext;
    }

    public byte[] decrypt(byte[] key, byte[] ciphertext) {
        // CTR mode decryption is identical to encryption
        return encrypt(key, ciphertext);
    }

    public byte[] prg(byte[] key) {
        byte[] iv = new byte[16];
        byte[] zeroInput = new byte[1024];
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
        Mac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);

        byte[] out = new byte[hmac.getMacSize()];
        hmac.doFinal(out, 0);
        return out;
    }

    public byte[] hash(byte[] data) {
        SHA256Digest digest = new SHA256Digest();
        byte[] output = new byte[digest.getDigestSize()];

        digest.update(data, 0, data.length);
        digest.doFinal(output, 0);

        return output;
    }

    public byte[] getAesKey(ECPoint s) {
        byte[] prefix = "aes_key:".getBytes();
        byte[] printable = group.printable(s);

        byte[] data = concatenate(prefix, printable);
        byte[] hash = hash(data);

        return slice(hash, keyLength);
    }

    public byte[] deriveKey(byte[] k, byte[] flavor) {
        byte[] m = new byte[keyLength];

        return aesCtr(k, m, flavor);
    }

    public BigInteger hb(ECPoint alpha, byte[] k) {
        byte[] flavor = "hbhbhbhbhbhbhbhb".getBytes();
        byte[] K = deriveKey(k, flavor);

        return group.makeexp(K);
    }

    public byte[] hrho(byte[] k) {
        byte[] flavor = "hrhohrhohrhohrho".getBytes();

        return deriveKey(k, flavor);
    }

    public byte[] hmu(byte[] k) {
        byte[] flavor = "hmu:hmu:hmu:hmu:".getBytes();

        return deriveKey(k, flavor);
    }

    public byte[] hpi(byte[] k) {
        byte[] flavor = "hpi:hpi:hpi:hpi:".getBytes();

        return deriveKey(k, flavor);
    }

    public byte[] htau(byte[] k) {
        byte[] flavor = "htauhtauhtauhtau".getBytes();

        return deriveKey(k, flavor);
    }
}
