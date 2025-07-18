package MasterThesisFormat.MixFormats.PolySphinx;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import MasterThesisFormat.crypto.ECCGroup;
import MasterThesisFormat.header.InstructionHeader;
import javasphinx.SphinxException;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PolySphinxUtil {

    private static class SubHeader {
        public final byte[] nextHop;
        public final byte[] omega;
        public final byte[] alpha;
        public final byte[] instructions;
        public final byte[] MAC;

        public SubHeader(byte[] nextHop, byte[] omega, byte[] alpha, byte[] instructions, byte[] MAC) {
            this.nextHop = nextHop;
            this.omega = omega;
            this.alpha = alpha;
            this.instructions = instructions;
            this.MAC = MAC;
        }
    }

    // erste Mix-Node, ist die replicationNode
    // suffixPaths sind die Pfade von der Replication-Node zu jedem Empfänger
    public static InstructionPacket createPolySphinxPacket(Params params, byte[] replicationNode, List<byte[][]> suffixPaths, byte[] message, byte[] seed, List<ECPoint[]> keys) throws IOException, SphinxException {
        ECCGroup group = params.getGroup();



        byte[] payload = message.clone();
        byte[] K = params.hash(seed);
        byte[] key = params.hash(K);
        byte[] encryptedPayload = params.encrypt(key, payload);

        List<SubHeader> subheaders = buildSubHeaderList(params, seed, suffixPaths, keys);

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

        //TODO verschlüsselt wird mit dem Shared secret!
        byte[] encInstr = params.encrypt(key, instructions);
        byte[] mac = params.mac(params.hmu(key), instructions);
        ECPoint alpha0 = group.expon(group.getGenerator(), group.genSecret());

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

    private static List<SubHeader> buildSubHeaderList(Params params, byte[] seed, List<byte[][]> suffixPaths, List<ECPoint[]> keys) throws IOException, SphinxException {
        List<SubHeader> subheaders = new ArrayList<>();
        ECCGroup group = params.getGroup();

        for (int pathIndex = 0; pathIndex < suffixPaths.size(); pathIndex++) {
            byte[][] nodeList = suffixPaths.get(pathIndex);
            ECPoint[] pubKeys = keys.get(pathIndex);

            SubHeader sh = buildSingleSubHeader(params, group, seed, nodeList, pubKeys, pathIndex, suffixPaths.size());
            if (sh != null) {
                subheaders.add(sh);
            }
        }

        return subheaders;
    }

    private static SubHeader buildSingleSubHeader(Params params, ECCGroup group, byte[] seed, byte[][] nodeList, ECPoint[] pubKeys, int pathIndex, int numberOfPaths) throws IOException, SphinxException {
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

        byte[] nextHop = Arrays.copyOf(nodeList[0], params.keyLength());

        byte[] onion = new byte[0];
        for (int i = nodeList.length - 1; i >= 0; i--) {
            byte[] instr;

            //Letzte Mix node = Exit Node
            if (i == nodeList.length - 1) {
                byte r = (byte) (nodeList.length - 1);
                byte log2p = (byte) Integer.toBinaryString(numberOfPaths).length();
                instr = PolySphinxInstructionPresets.createExitInstructions(seed, path, nodeList[i], r, log2p, (byte) params.keyLength());
            } else {
                instr = PolySphinxInstructionPresets.createRelayInstructions(nodeList[i + 1], sigmas[i + 1]);
            }

            byte[] plain = new byte[instr.length + onion.length];
            System.arraycopy(instr, 0, plain, 0, instr.length);
            System.arraycopy(onion, 0, plain, instr.length, onion.length);

            byte[] enc = params.xorRho(params.hrho(secrets[i]), plain);
            byte[] gamma = params.mu(params.hmu(secrets[i]), plain);

            onion = new byte[gamma.length + enc.length];
            System.arraycopy(gamma, 0, onion, 0, gamma.length);
            System.arraycopy(enc, 0, onion, gamma.length, enc.length);
        }

        byte[] finalMac = Arrays.copyOfRange(onion, 0, params.keyLength());
        byte[] finalInstr = Arrays.copyOfRange(onion, params.keyLength(), onion.length);
        byte[] alphaBytes = SerializationUtils.encodeECPoint(alphas[0]);

        return new SubHeader(nextHop, sigmas[0], alphaBytes, finalInstr, finalMac);
    }

}
