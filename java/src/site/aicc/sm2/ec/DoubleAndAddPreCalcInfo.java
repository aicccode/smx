package site.aicc.sm2.ec;

/** Pre-computation info for the double-and-add multiplier. */
public class DoubleAndAddPreCalcInfo extends AbstractECPreCalcInfo {

    protected AbstractECPoint offset = null;

    protected int width = -1;

    public AbstractECPoint getOffset() {
        return offset;
    }

    public void setOffset(AbstractECPoint offset) {
        this.offset = offset;
    }

    public int getWidth() {
        return width;
    }

    public void setWidth(int width) {
        this.width = width;
    }
}
