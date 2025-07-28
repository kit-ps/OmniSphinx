package MasterThesisFormat.MixFormats.PolySphinx;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import MasterThesisFormat.crypto.ECCGroup;
import MasterThesisFormat.header.InstructionEncryptor;
import MasterThesisFormat.header.InstructionHeader;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static MasterThesisFormat.SerializationUtils.concatenate;
import static MasterThesisFormat.SerializationUtils.slice;

public class PolySphinxUtil {

    // erste Mix-Node, ist die replicationNode
    // suffixPaths sind die Pfade von der Replication-Node zu jedem Empfänger
    public static InstructionPacket createPolySphinxPacket(Params params, byte[] replicationNode, ECPoint replicationNodePubKey, List<byte[][]> suffixPaths, byte[] message, byte[] seed, List<ECPoint[]> keys) throws Exception {
        ECCGroup group = params.getGroup();



        byte[] payload = message.clone();
        byte[] K = params.hash(seed);
        byte[] key = params.hash(K);
        byte[] encryptedPayload = params.encrypt(key, payload);

        BigInteger r = group.genSecret();
        ECPoint alpha0 = group.expon(group.getGenerator(), r);
        ECPoint sharedSecret = group.expon(replicationNodePubKey, r);
        byte[] sharedSecretKey = params.getAesKey(sharedSecret);

        List<SubHeader> subheaders = buildSubHeaderList(params, seed, suffixPaths, keys, sharedSecretKey);

        ByteArrayOutputStream shOut = new ByteArrayOutputStream();
        for (SubHeader sh : subheaders) {
            shOut.write(sh.nextHop);
            shOut.write(sh.omega);
            shOut.write(sh.alpha);
            shOut.write(sh.MAC);
            shOut.write(sh.instructions);
        }
        byte[] B = shOut.toByteArray();

        byte kappaLen = (byte) params.keyLength();
        byte p = (byte) subheaders.size();
        byte tauPost = subheaders.isEmpty() ? 0 : (byte) subheaders.get(0).instructions.length;
        byte[] instructions = PolySphinxInstructionPresets.createReplicationInstructions(kappaLen, (byte) (2*kappaLen), p, tauPost, B);

        if (instructions.length > params.getInstructionTotalSize()) {
            throw new IllegalArgumentException("Replication instructions exceed allowed size");
        }

        int padLen = params.getInstructionTotalSize() - instructions.length;
        byte[] padding = InstructionEncryptor.padInstructions(params, padLen, instructions.length, sharedSecretKey, 0);

        byte[] encInstr = params.xorRho(params.hrho(sharedSecretKey), instructions);
        encInstr = concatenate(encInstr, padding);
        byte[] mac = params.mac(params.hmu(sharedSecretKey), encInstr);

        InstructionHeader header = new InstructionHeader(alpha0, encInstr, mac);

        return new InstructionPacket(header, encryptedPayload);
    }

    public static byte[] keyTreeKey(Params params, byte[] seed, byte[] path) {
        byte[] current = params.hash(seed);

        for (byte p : path) {
            for (int i = 0; i <= (p & 0xFF); i++) {
                increment(current);
            }
            current = params.hash(current);
        }

        return current;
    }

    private static void increment(byte[] x) {
        for (int i = x.length - 1; i >= 0; i--) {
            x[i]++;
            if (x[i] != 0) break;
        }
    }

    private static List<SubHeader> buildSubHeaderList(Params params, byte[] seed, List<byte[][]> suffixPaths, List<ECPoint[]> keys, byte[] replicationSecret) throws Exception {
        List<SubHeader> subheaders = new ArrayList<>();
        ECCGroup group = params.getGroup();

        for (int pathIndex = 0; pathIndex < suffixPaths.size(); pathIndex++) {
            byte[][] nodeList = suffixPaths.get(pathIndex);
            ECPoint[] pubKeys = keys.get(pathIndex);

            SubHeader sh = buildSingleSubHeader(params, group, seed, nodeList, pubKeys, pathIndex, suffixPaths.size(), replicationSecret);
            if (sh != null) {
                subheaders.add(sh);
            }
        }

        return subheaders;
    }

    private static SubHeader buildSingleSubHeader(Params params, ECCGroup group, byte[] seed, byte[][] nodeList, ECPoint[] pubKeys, int pathIndex, int numberOfPaths, byte[] replicationSecret) throws Exception {
        BigInteger x = group.genSecret();

        ECPoint[] alphas = new ECPoint[nodeList.length];
        ECPoint[] sharedSecrets = new ECPoint[nodeList.length];
        byte[][] secrets = new byte[nodeList.length][];
        byte[][] sigmas = new byte[nodeList.length][];
        byte[] path = new byte[1];
        path[0] = (byte) (pathIndex + 1);

        for (int i = 0; i < nodeList.length; i++) {
            alphas[i] = group.expon(group.getGenerator(), x);
            sharedSecrets[i] = group.expon(pubKeys[i], x);
            secrets[i] = params.getAesKey(sharedSecrets[i]);
            BigInteger b = params.hb(alphas[i], secrets[i]);
            x = x.multiply(b).mod(group.getOrder());

            byte[] sigma = keyTreeKey(params, seed, path);
            sigmas[i] = params.hash(sigma);

            path = Arrays.copyOf(path, path.length + 1);
            path[path.length - 1] = (byte) 1;
        }

        if (nodeList.length == 0) {
            return null;
        }

        byte[][] instructions = new byte[nodeList.length][];
        for (int i = nodeList.length - 1; i >= 0; i--) {
            //Letzte Mix node = Exit Node
            if (i == nodeList.length - 1) {
                byte r = (byte) (nodeList.length - 1);
                byte log2p = (byte) Integer.toBinaryString(numberOfPaths).length();
                instructions[i] = PolySphinxInstructionPresets.createExitInstructions(seed, path, nodeList[i], r, log2p, (byte) params.keyLength());
            } else {
                instructions[i] = PolySphinxInstructionPresets.createRelayInstructions(nodeList[i + 1], sigmas[i + 1]);
            }
        }

        int instructionLength = 0;
        for(byte[] instruction: instructions) {
            instructionLength += instruction.length;
        }
        int toPad = params.getInstructionTotalSize() - instructionLength;

        // compute padding for replication node but do not append
        byte[] padding = InstructionEncryptor.padInstructions(params, toPad, instructionLength, replicationSecret, pathIndex);

        byte[] onion = InstructionEncryptor.encryptWithPadding(params, instructions, secrets, params.getInstructionTotalSize(), padding);

        byte[] encInstructions = slice(onion, instructionLength);

        byte[] finalMac = params.mu(params.hmu(secrets[0]), concatenate(encInstructions, padding));
        byte[] alphaBytes = SerializationUtils.encodeECPoint(alphas[0]);
        byte[] nextHop = Arrays.copyOf(nodeList[0], params.keyLength());

        return new SubHeader(nextHop, sigmas[0], alphaBytes, encInstructions, finalMac);
    }

}
