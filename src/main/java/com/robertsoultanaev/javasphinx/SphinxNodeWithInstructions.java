package com.robertsoultanaev.javasphinx;

import com.robertsoultanaev.javasphinx.VM.SphinxVM;
import com.robertsoultanaev.javasphinx.packet.ProcessedPacket;
import com.robertsoultanaev.javasphinx.packet.SphinxPacket;
import com.robertsoultanaev.javasphinx.packet.header.PacketContent;
import com.robertsoultanaev.javasphinx.packet.instruction.SphinxInstructionPresets;

import java.io.IOException;
import java.math.BigInteger;

public class SphinxNodeWithInstructions {

    private final BigInteger nodeSecret;

    public SphinxNodeWithInstructions(BigInteger nodeSecret) {
        this.nodeSecret = nodeSecret;
    }

    /**
     * Verarbeitet ein Sphinx-Paket mithilfe der SphinxVM und vordefinierter Instruktionen.
     */
    public ProcessedPacket process(PacketContent packetContent) throws Exception {
        //SphinxVM vm = new SphinxVM(nodeSecret);
        //byte[] instructions = SphinxInstructionPresets.createInstructions();

        //SphinxPacket packet = new SphinxPacket(null, packetContent); // params werden ggf. in VM oder anders übergeben
        //return vm.interpret(packet, instructions);
        return null;
    }
}
