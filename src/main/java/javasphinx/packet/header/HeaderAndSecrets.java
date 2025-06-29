package javasphinx.packet.header;

import org.bouncycastle.math.ec.ECPoint;

import java.util.List;

/**
 * Type to combine Sphinx header, alphas and secrets used to encrypt the Sphinx payload
 * secrets = AesKeys, not the shared secret s!
 */
public record HeaderAndSecrets(SphinxHeader sphinxHeader, byte[][] secrets, ECPoint[] alpha) {
}
