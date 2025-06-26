package javasphinx.pki;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public record PkiEntry(BigInteger priv, ECPoint pub) {
}
