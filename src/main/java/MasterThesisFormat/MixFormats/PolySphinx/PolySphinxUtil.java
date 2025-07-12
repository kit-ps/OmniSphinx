package MasterThesisFormat.MixFormats.PolySphinx;

import MasterThesisFormat.InstructionPacket.InstructionPacket;
import MasterThesisFormat.Params;
import MasterThesisFormat.SerializationUtils;
import MasterThesisFormat.crypto.ECCGroup;
import MasterThesisFormat.header.InstructionHeader;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PolySphinxUtil {

    private static class SubHeader {
        public final byte[] alpha;
        public final byte[] instructions;
        public final byte[] MAC;

        public SubHeader(byte[] alpha, byte[] instructions, byte[] MAC) {
            this.alpha = alpha;
            this.instructions = instructions;
            this.MAC = MAC;
        }
    }

    // erste Mix-Node, ist die replicationNode
    // suffixPaths sind die Pfade von der Replication-Node zu jedem Empfänger
    public static InstructionPacket createPolySphinxPacket(Params params, byte[] replicationNode, List<byte[][]> suffixPaths, byte[] message, byte[] seed, List<ECPoint[]> keys) throws IOException {
        ECCGroup group = params.getGroup();



        byte[] payload = message.clone();
        byte[] K = params.hash(seed);
        byte[] encryptedPayload = params.encrypt(K, payload);

        List<SubHeader> subheaders = new ArrayList<>();

        for (int pathIndex = 0; pathIndex < suffixPaths.size(); pathIndex++) {
            BigInteger x = group.genSecret();

            byte[][] nodelist = suffixPaths.get(pathIndex);
            ECPoint[] pubKeys = keys.get(pathIndex);
            ECPoint[] alphas = new ECPoint[nodelist.length];
            ECPoint[] sharedSecrets = new ECPoint[nodelist.length];
            byte[][] secrets = new byte[nodelist.length][];
            byte[][] sigmas = new byte[nodelist.length][];
            byte[] pathPrefix = new byte[0];
            for (int i = 0; i < nodelist.length; i++) {
                alphas[i] = group.expon(group.getGenerator(), x);
                sharedSecrets[i] = group.expon(pubKeys[i], x);
                secrets[i] = params.getAesKey(sharedSecrets[i]);
                BigInteger b = params.hb(alphas[i], secrets[i]);
                x = x.multiply(b).mod(group.getOrder());

                byte[] sigma = keyTreeKey(params, seed, pathPrefix);
                sigmas[i] = sigma;

                pathPrefix = Arrays.copyOf(pathPrefix, pathPrefix.length + 1);
                pathPrefix[pathPrefix.length - 1] = (byte) (1);
            }

            if (nodelist.length > 0) {
                byte[] nextHop = Arrays.copyOf(nodelist[0], params.keyLength());
                byte[] omega = Arrays.copyOf(sigmas[0], params.keyLength());
                byte[] alphaBytes = Arrays.copyOf(SerializationUtils.encodeECPoint(alphas[0]), params.keyLength());
                subheaders.add(new SubHeader(nextHop, omega, alphaBytes));
            }

        }

        ByteArrayOutputStream shOut = new ByteArrayOutputStream();
        for (SubHeader sh : subheaders) {
            //shOut.write(sh.nextHop);
            //shOut.write(sh.omega);
            shOut.write(sh.alpha);
        }
        byte[] B = shOut.toByteArray();

        byte kappaLen = (byte) params.keyLength();
        byte p = (byte) subheaders.size();
        byte tauPost = (byte) params.headerLength();
        byte[] instructions = PolySphinxInstructionPresets.createReplicationInstructions(kappaLen, p, tauPost, B);

        byte[] encInstr = params.encrypt(K, instructions);
        byte[] mac = params.mac(params.hmu(K), instructions);
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

    private SubHeader createSubHeader(Params params, int index, byte[] nextHop, byte[] seed, byte[] alpha) throws IOException {
        byte[] pathIndex = new byte[]{(byte) index};
        byte[] omega = keyTreeKey(params, seed, pathIndex);

        return new SubHeader(nextHop, omega, alpha);
    }

}
