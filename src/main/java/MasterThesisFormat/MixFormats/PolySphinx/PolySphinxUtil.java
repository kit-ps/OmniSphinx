package MasterThesisFormat.MixFormats.PolySphinx;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import MasterThesisFormat.crypto.ECCGroup;
import MasterThesisFormat.header.InstructionEncryptor;
import MasterThesisFormat.header.InstructionHeader;
import kotlin.Pair;
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
    public static InstructionPacket createPolySphinxPacket(Params params, byte[] replicationNode, ECPoint replicationNodePubKey, List<byte[][]> suffixPaths, List<byte[]> receivers, byte[] message, byte[] seed, List<ECPoint[]> keys) throws Exception {
        ECCGroup group = params.getGroup();



        byte[] payload = message.clone();
        byte[] K = params.hash(seed);
        byte[] key = params.hash(K);
        byte[] encryptedPayload = params.encrypt(key, payload);

        BigInteger r = group.genSecret();
        ECPoint alpha0 = group.expon(group.getGenerator(), r);
        ECPoint sharedSecret = group.expon(replicationNodePubKey, r);
        byte[] sharedSecretKey = params.getAesKey(sharedSecret);

        List<SubHeader> subheaders = buildSubHeaderList(params, seed, suffixPaths, receivers, keys, sharedSecretKey);

        ByteArrayOutputStream shOut = new ByteArrayOutputStream();
        for (SubHeader sh : subheaders) {
            shOut.write(sh.nextHop);
            shOut.write(sh.omega);
            shOut.write(sh.alpha);
            shOut.write(sh.MAC);
            shOut.write(sh.instructions);
        }
        byte[] B = shOut.toByteArray();

        int nextHopLen = subheaders.isEmpty() ? 0 : subheaders.get(0).nextHop.length;
        int keyLen = subheaders.isEmpty() ? 0 : subheaders.get(0).omega.length;
        int alphaLen = subheaders.isEmpty() ? 0 : subheaders.get(0).alpha.length;
        int gammaLen = subheaders.isEmpty() ? 0 : subheaders.get(0).MAC.length;
        int p = subheaders.size();
        int tauPost = subheaders.isEmpty() ? 0 : subheaders.get(0).instructions.length;
        byte[] instructions = PolySphinxInstructionPresets.createReplicationInstructions(nextHopLen, keyLen, alphaLen, gammaLen, p, tauPost, B);

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

    private static List<SubHeader> buildSubHeaderList(Params params, byte[] seed, List<byte[][]> suffixPaths, List<byte[]> receivers, List<ECPoint[]> keys, byte[] replicationSecret) throws Exception {
        List<SubHeader> subheaders = new ArrayList<>();
        ECCGroup group = params.getGroup();

        if (suffixPaths.size() != receivers.size()) {
            throw new IllegalArgumentException("Each suffix path must have a corresponding receiver");
        }


        for (int pathIndex = 0; pathIndex < suffixPaths.size(); pathIndex++) {
            byte[][] nodeList = suffixPaths.get(pathIndex);
            ECPoint[] pubKeys = keys.get(pathIndex);
            byte[] receiver = receivers.get(pathIndex);

            SubHeader sh = buildSingleSubHeader(params, group, seed, nodeList, pubKeys, receiver, pathIndex, suffixPaths.size(), replicationSecret);
            if (sh != null) {
                subheaders.add(sh);
            }
        }

        return subheaders;
    }




    private static void increment(byte[] x) {
        for (int i = x.length - 1; i >= 0; i--) {
            x[i]++;
            if (x[i] != 0) break;
        }
    }

    public static byte[] keyTreeKey(Params params, byte[] seed, byte[] path) {
        byte[] current = params.hash(seed);

        for (byte p : path) {
            for (int i = 0; i < (p & 0xFF); i++) {
                increment(current);
            }
            current = params.hash(current);
        }

        return current;
    }

    private static SubHeader buildSingleSubHeader(Params params, ECCGroup group, byte[] seed, byte[][] nodeList, ECPoint[] pubKeys, byte[] receiver, int pathIndex, int numberOfPaths, byte[] replicationSecret) throws Exception {        BigInteger x = group.genSecret();

        int hops = nodeList.length;
        ECPoint[] alphas = new ECPoint[nodeList.length];
        ECPoint[] sharedSecrets = new ECPoint[nodeList.length];
        byte[][] secrets = new byte[nodeList.length][];
        byte[][] sigmas = new byte[nodeList.length][];
        byte[] path = new byte[1];
        path[0] = (byte) (pathIndex + 1);

        for (int i = 0; i < hops; i++) {
            alphas[i] = group.expon(group.getGenerator(), x);
            sharedSecrets[i] = group.expon(pubKeys[i], x);
            secrets[i] = params.getAesKey(sharedSecrets[i]);
            BigInteger b = params.hb(alphas[i], secrets[i]);
            x = x.multiply(b).mod(group.getOrder());

            byte[] sigma = keyTreeKey(params, seed, path);
            sigmas[i] = sigma;

            if(i != hops - 1) {
                path = Arrays.copyOf(path, path.length + 1);
                path[path.length - 1] = (byte) 1;
            }

        }

        if (nodeList.length == 0) {
            return null;
        }

        // create Instruction header
        byte[][] instructions = new byte[nodeList.length][];
        for (int i = 0; i < hops; i++) {
            //Letzte Mix node = Exit Node
            if (i == hops - 1) {
                byte r = (byte) path.length;
                int log2p = 1;
                instructions[i] = PolySphinxInstructionPresets.createExitInstructions(seed, path, receiver, r, log2p, (byte) params.keyLength());
            } else {
                instructions[i] = PolySphinxInstructionPresets.createRelayInstructions(nodeList[i+1], sigmas[i+1]);
            }
        }

        int headerLen = 0;
        for (int i = 0; i < hops; i++) {
            headerLen += instructions[i].length;
            if (i < hops - 1) {
                headerLen += params.keyLength(); // only non-exit hops include a gamma value
            }
        }

        int instPadLen = params.getInstructionTotalSize() - headerLen;

        // compute padding for replication node but do not append
        byte[] padding = InstructionEncryptor.padInstructions(params, instPadLen, headerLen, replicationSecret, pathIndex);

        byte[] onion = InstructionEncryptor.encryptWithPadding(params, instructions, secrets, params.getInstructionTotalSize(), padding);

        byte[] encInstructions = slice(onion, headerLen);

        byte[] finalMac = params.mac(params.hmu(secrets[0]), concatenate(encInstructions, padding));

        byte[] alphaBytes = SerializationUtils.encodeECPoint(alphas[0]);
        byte[] nextHop = Arrays.copyOf(nodeList[0], params.keyLength());

        return new SubHeader(nextHop, sigmas[0], alphaBytes, encInstructions, finalMac);
    }

    public static Pair<InstructionPacket, List<SubHeader>> createPolySphinxPacketForTests(Params params, byte[] replicationNode, ECPoint replicationNodePubKey, List<byte[][]> suffixPaths, List<byte[]> receivers, byte[] message, byte[] seed, List<ECPoint[]> keys) throws Exception {        ECCGroup group = params.getGroup();



        byte[] payload = message.clone();
        byte[] K = params.hash(seed);
        byte[] key = params.hash(K);
        byte[] encryptedPayload = params.encrypt(key, payload);

        BigInteger r = group.genSecret();
        ECPoint alpha0 = group.expon(group.getGenerator(), r);
        ECPoint sharedSecret = group.expon(replicationNodePubKey, r);
        byte[] sharedSecretKey = params.getAesKey(sharedSecret);

        List<SubHeader> subheaders = buildSubHeaderList(params, seed, suffixPaths, receivers, keys, sharedSecretKey);

        ByteArrayOutputStream shOut = new ByteArrayOutputStream();
        for (SubHeader sh : subheaders) {
            shOut.write(sh.nextHop);
            shOut.write(sh.omega);
            shOut.write(sh.alpha);
            shOut.write(sh.MAC);
            shOut.write(sh.instructions);
        }
        byte[] B = shOut.toByteArray();

        int nextHopLen = subheaders.isEmpty() ? 0 : subheaders.get(0).nextHop.length;
        int keyLen = subheaders.isEmpty() ? 0 : subheaders.get(0).omega.length;
        int alphaLen = subheaders.isEmpty() ? 0 : subheaders.get(0).alpha.length;
        int gammaLen = subheaders.isEmpty() ? 0 : subheaders.get(0).MAC.length;
        int p = subheaders.size();
        int tauPost = subheaders.isEmpty() ? 0 : subheaders.get(0).instructions.length;
        byte[] instructions = PolySphinxInstructionPresets.createReplicationInstructions(nextHopLen, keyLen, alphaLen, gammaLen, p, tauPost, B);

        if (instructions.length > params.getInstructionTotalSize()) {
            throw new IllegalArgumentException("Replication instructions exceed allowed size");
        }

        int padLen = params.getInstructionTotalSize() - instructions.length;
        byte[] padding = InstructionEncryptor.padInstructions(params, padLen, instructions.length, sharedSecretKey, 0);

        byte[] encInstr = params.xorRho(params.hrho(sharedSecretKey), instructions);
        encInstr = concatenate(encInstr, padding);
        byte[] mac = params.mac(params.hmu(sharedSecretKey), encInstr);

        InstructionHeader header = new InstructionHeader(alpha0, encInstr, mac);

        InstructionPacket packet = new InstructionPacket(header, encryptedPayload);
        return new Pair<>(packet, subheaders);
    }
}
