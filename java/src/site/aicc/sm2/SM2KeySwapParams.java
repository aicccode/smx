package site.aicc.sm2;

import site.aicc.sm2.ec.AbstractECPoint;

/** SM2 key exchange protocol parameters. */
public class SM2KeySwapParams {
    private String sa, sb;
    private String ka, kb;
    private AbstractECPoint v;
    private byte[] za, zb;
    private boolean success;
    private String message;

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public AbstractECPoint getV() {
        return v;
    }

    public void setV(AbstractECPoint v) {
        this.v = v;
    }

    public byte[] getZb() {
        return zb;
    }

    public void setZb(byte[] zb) {
        this.zb = zb;
    }

    public byte[] getZa() {
        return za;
    }

    public void setZa(byte[] za) {
        this.za = za;
    }

    public String getSa() {
        return sa;
    }

    public void setSa(String sa) {
        this.sa = sa;
    }

    public String getSb() {
        return sb;
    }

    public void setSb(String sb) {
        this.sb = sb;
    }

    public String getKa() {
        return ka;
    }

    public void setKa(String ka) {
        this.ka = ka;
    }

    public String getKb() {
        return kb;
    }

    public void setKb(String kb) {
        this.kb = kb;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
