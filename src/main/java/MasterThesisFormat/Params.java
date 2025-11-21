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
        this(16, 1024, 192, new ECCGroup(), 1024);
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
