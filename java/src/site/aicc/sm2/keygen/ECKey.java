package site.aicc.sm2.keygen;

/** SM2 key base class. */
public class ECKey {
    private boolean privateKey;

    protected ECKey(boolean isPrivate) {
        this.setPrivateKey(isPrivate);
    }

    public boolean isPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(boolean privateKey) {
        this.privateKey = privateKey;
    }
}
