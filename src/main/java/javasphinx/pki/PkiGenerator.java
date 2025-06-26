package javasphinx.pki;

import javasphinx.SphinxParams;

public class PkiGenerator {

    private final SphinxParams params;

    public PkiGenerator(final SphinxParams params) {
        this.params = params;
    }

    public PkiEntry generateKeyPair() {
        final var priv = params.generatePrivateKey();
        final var pub = params.derivePublicKey(priv);
        return new PkiEntry(priv, pub);
    }
}
