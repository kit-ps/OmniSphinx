import javasphinx.SerializationUtils;
import javasphinx.SphinxException;
import javasphinx.SphinxParams;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SphinxParamsTest {

    private SphinxParams params;
    private byte[] key;
    private byte[] plaintext;

    @Before
    public void setUp() {
        params = new SphinxParams();
        key = Hex.decode("5f060d3716b345c253f6749abac10917");
        plaintext = Hex.decode("265f3338efbf92c9feacf25fb10778b6d96996e72b41c4e4f55f373d182ba4e1acd5b972e95a917da9f6946924aab6e0b926b94996c25bea7e00422d1f11468578b60f460cb5ce2eafa72fef8cb1a2de");
    }

    @Test
    public void aesCtrEncrypt() {
        byte[] iv = Hex.decode("18e3e4c93f5bdd1fb4961630309206e6");

        byte[] expectedOutput = Hex.decode("fbf3df496e16a07c149c197a1772e9901a7fbac16a9424c6282ed06624e4fdec5b2c1c50a347fb782647c8bce5b9a04b32a3eaa1c2d2aae082aad017103aa212e32569a45f0436ff4a5ea95c52522c92");
        byte[] output = params.aesCtr(key, plaintext, iv);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void aesCtrEncryptNoIV() {
        byte[] expectedOutput = Hex.decode("0e000098e34558b1c728b1580787f881012f2a1eaf3ac383fd596b13d87a95cce1376225b739b15e630f89fe64dbc54752a22ed567f1b368cae6aa1c374fdb008602fbbe5b1cfe3c7c256669e080903d");
        byte[] output = params.aesCtr(key, plaintext);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void aesCtrEncryptThenDecrypt() {
        byte[] iv = Hex.decode("18e3e4c93f5bdd1fb4961630309206e6");

        byte[] ciphertext = params.aesCtr(key, plaintext, iv);
        byte[] decryptedCiphertext = params.aesCtr(key, ciphertext, iv);

        assertArrayEquals(plaintext, decryptedCiphertext);
    }

    @Test
    public void lionessEncrypt() throws SphinxException {
        byte[] expectedOutput = Hex.decode("937e52902f5300c07b0dbd39d4e10b9d0de98278ed16d2ef2f4652d5318041da6d16188c11f4dbfba12b36f7e23a1a8daebff5942703463241d7ed2c909116e913bb9f74d645fb8d99971f299d21ac51");
        byte[] output = params.lionessEnc(key, plaintext);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void lionessEncryptThenDecrypt() throws SphinxException {
        byte[] ciphertext = params.lionessEnc(key, plaintext);
        byte[] decryptedCiphertext = params.lionessDec(key, ciphertext);

        assertArrayEquals(plaintext, decryptedCiphertext);
    }

    @Test(expected = SphinxException.class)
    public void lionessEncryptBadKeyLength() throws SphinxException {
        byte[] badKey = Arrays.copyOf(key, key.length - 1);
        params.lionessEnc(badKey, plaintext);
    }

    @Test(expected = SphinxException.class)
    public void lionessEncryptBadMessageLength() throws SphinxException {
        byte[] badMessage = Arrays.copyOf(plaintext, (key.length / 2) - 1);
        params.lionessEnc(key, badMessage);
    }

    @Test(expected = SphinxException.class)
    public void lionessDecryptBadKeyLength() throws SphinxException {
        byte[] ciphertext = params.lionessEnc(key, plaintext);

        byte[] badKey = Arrays.copyOf(key, key.length - 1);
        params.lionessDec(badKey, ciphertext);
    }

    @Test(expected = SphinxException.class)
    public void lionessDecryptBadMessageLength() throws SphinxException {
        byte[] ciphertext = params.lionessEnc(key, plaintext);
        byte[] badMessage = Arrays.copyOf(ciphertext, (key.length / 2) - 1);

        params.lionessDec(key, badMessage);
    }

    @Test
    public void xorRho() throws SphinxException {
        byte[] expectedOutput = Hex.decode("0e000098e34558b1c728b1580787f881012f2a1eaf3ac383fd596b13d87a95cce1376225b739b15e630f89fe64dbc54752a22ed567f1b368cae6aa1c374fdb008602fbbe5b1cfe3c7c256669e080903d");
        byte[] output = params.xorRho(key, plaintext);

        assertArrayEquals(expectedOutput, output);
    }

    @Test(expected = SphinxException.class)
    public void xorRhoBadKeyLength() throws SphinxException {
        byte[] badKey = Arrays.copyOf(key, key.length - 1);
        params.xorRho(badKey, plaintext);
    }

    @Test
    public void mu() {
        byte[] expectedOutput = Hex.decode("90993216df7f52e7a2ea9db410a462fd");
        byte[] output = params.mu(key, plaintext);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void piEncryptThenDecrypt() throws SphinxException {
        SecureRandom random = new SecureRandom();
        byte[] plaintext = new byte[params.bodyLength()];
        random.nextBytes(plaintext);

        byte[] ciphertext = params.pi(key, plaintext);
        byte[] decryptedCiphertext = params.pii(key, ciphertext);

        assertArrayEquals(plaintext, decryptedCiphertext);
    }

    @Test(expected = SphinxException.class)
    public void piEncryptBadKeyLength() throws SphinxException {
        SecureRandom random = new SecureRandom();
        byte[] plaintext = new byte[params.bodyLength()];
        random.nextBytes(plaintext);

        byte[] badKey = Arrays.copyOf(key, key.length - 1);

        params.pi(badKey, plaintext);
    }

    @Test(expected = SphinxException.class)
    public void piEncryptBadMessageLength() throws SphinxException {
        SecureRandom random = new SecureRandom();
        byte[] plaintext = new byte[params.bodyLength() - 1];
        random.nextBytes(plaintext);

        params.pi(key, plaintext);
    }

    @Test(expected = SphinxException.class)
    public void piDecryptBadKeyLength() throws SphinxException {
        SecureRandom random = new SecureRandom();
        byte[] plaintext = new byte[params.bodyLength()];
        random.nextBytes(plaintext);

        byte[] ciphertext = params.pi(key, plaintext);

        byte[] badKey = Arrays.copyOf(key, key.length - 1);
        params.pii(badKey, ciphertext);
    }

    @Test(expected = SphinxException.class)
    public void piDecryptBadMessageLength() throws SphinxException {
        SecureRandom random = new SecureRandom();
        byte[] plaintext = new byte[params.bodyLength()];
        random.nextBytes(plaintext);

        byte[] ciphertext = params.pi(key, plaintext);
        byte[] badCiphertext = Arrays.copyOf(ciphertext, ciphertext.length - 1);
        params.pii(key, badCiphertext);
    }

    @Test
    public void hash() {
        byte[] expectedOutput = Hex.decode("75cab8f34fc4fed6ad3dd420b1f558a9c55549496316ded97f6bdbf6c5b201e1");
        byte[] output = params.hash(plaintext);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void getAesKey() {
        byte[] encodedEcPoint = Hex.decode("02a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae2");
        ECPoint s = SerializationUtils.decodeECPoint(encodedEcPoint);

        byte[] expectedOutput = Hex.decode("ef9706c84715d56800ef8fceb5671d55");
        byte[] output = params.getAesKey(s);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void deriveKey() {
        byte[] flavor = "aaaaaaaaaaaaaaaa".getBytes(StandardCharsets.US_ASCII);

        byte[] expectedOutput = Hex.decode("89d2eb817c3a90755cc952254323c342");
        byte[] output = params.deriveKey(key, flavor);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void hb() {
        byte[] encodedEcPoint = Hex.decode("02a66335a59f1277c193315eb2db69808e6eaf15c944286765c0adcae2");
        ECPoint alpha = SerializationUtils.decodeECPoint(encodedEcPoint);

        BigInteger expectedOutput = new BigInteger("99291632524521846780855783327754112432");
        BigInteger output = params.hb(alpha, key);

        assertEquals(expectedOutput, output);
    }

    @Test
    public void hrho() {
        byte[] expectedOutput = Hex.decode("a941fceaec8077174e46e0c1e40dc454");
        byte[] output = params.hrho(key);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void hmu() {
        byte[] expectedOutput = Hex.decode("be430289b8937b4ded6bf31f6e8ac891");
        byte[] output = params.hmu(key);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void hpi() {
        byte[] expectedOutput = Hex.decode("f74e9cf22a397c70c033cf47f2e63523");
        byte[] output = params.hpi(key);

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void htau() {
        byte[] expectedOutput = Hex.decode("5d6904bdc9c4fb34e30d8d807b130d82");
        byte[] output = params.htau(key);

        assertArrayEquals(expectedOutput, output);
    }

}
