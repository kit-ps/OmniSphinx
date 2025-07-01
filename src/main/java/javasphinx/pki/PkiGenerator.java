package javasphinx.pki;

import MasterThesisFormat.Params;

public class PkiGenerator {

    private final Params params;

    public PkiGenerator(final Params params) {
        this.params = params;
    }

    public PkiEntry generateKeyPair() {
        final var priv = params.generatePrivateKey();
        final var pub = params.derivePublicKey(priv);
        return new PkiEntry(priv, pub);
    }
}
