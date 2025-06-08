package com.robertsoultanaev.javasphinx.packet.header;

import org.bouncycastle.math.ec.ECPoint;

public record HeaderAndInstructions(
        ECPoint alpha,
        byte[] beta,
        byte[] gamma,
        byte[] instructions

) {
    public HeaderAndInstructions {
        if (alpha == null) throw new IllegalArgumentException("alpha cannot be null");
        if (beta == null) throw new IllegalArgumentException("beta cannot be null");
        if (gamma == null) throw new IllegalArgumentException("gamma cannot be null");

        // Defensive Kopien
        beta = beta.clone();
        gamma = gamma.clone();
        instructions = instructions.clone();
    }

    public byte[] getBeta() {
        return beta.clone();
    }

    public byte[] getGamma() {
        return gamma.clone();
    }

    public byte[] getInstructions() {
        return instructions.clone();
    }
}