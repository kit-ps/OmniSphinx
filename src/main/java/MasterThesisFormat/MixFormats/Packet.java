package MasterThesisFormat.MixFormats;



public abstract class Packet {
    private int headerLength;
    private int bodyLength;
    private Header header;
    private byte[] delta;

    public abstract int headerLength();
    public abstract int bodyLength();
    public abstract Header getHeader();
    public abstract byte[] getDelta();
}
