package site.aicc.sm2.ec;

/** Pre-computation info for EC point multipliers. */
public abstract class AbstractECPreCalcInfo {

    protected AbstractECPoint[] preComp = null;
    protected AbstractECPoint[] preCompNeg = null;
    protected AbstractECPoint twice = null;

    public AbstractECPoint[] getPreComp() {
        return preComp;
    }

    public void setPreComp(AbstractECPoint[] preComp) {
        this.preComp = preComp;
    }

    public AbstractECPoint[] getPreCompNeg() {
        return preCompNeg;
    }

    public void setPreCompNeg(AbstractECPoint[] preCompNeg) {
        this.preCompNeg = preCompNeg;
    }

    public AbstractECPoint getTwice() {
        return twice;
    }

    public void setTwice(AbstractECPoint twice) {
        this.twice = twice;
    }
}
