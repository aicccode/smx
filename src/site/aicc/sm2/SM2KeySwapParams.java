package site.aicc.sm2;

import site.aicc.sm2.ec.AbstractECPoint;

//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：SM2密钥交换协议传参用</h3>
*       <p>本类用于(For) : </p>
*     </li>
*     <li>
*       <h4> 使用示例(Example)：</h4>
*       <p></p>
*       <p></p>
*     </li>
*     <li>
*       <h3>版本历史</h3>
*       <ul>
*           <li>Version : 1.00</li>
*           <li>Date : 2020-10-04 | 下午11:34:30</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class SM2KeySwapParams {
    // A、B两侧计算出来需要发送给对方的验证值
    private String Sa, Sb;
    // A、B两侧计算出来的密钥，禁止发送!!!
    private String Ka, Kb;
    // B侧计算中间结果，保留用于验证A测返回的验证值
    private AbstractECPoint V;
    private byte[] Za,Zb;
    // 协商是否成功
    private boolean success;
    private String message;
    
    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public AbstractECPoint getV() {
        return V;
    }

    public void setV(AbstractECPoint v) {
        V = v;
    }

    public byte[] getZb() {
        return Zb;
    }

    public void setZb(byte[] zb) {
        Zb = zb;
    }

    public byte[] getZa() {
        return Za;
    }

    public void setZa(byte[] za) {
        Za = za;
    }

    public String getSa() {
        return Sa;
    }

    public void setSa(String sa) {
        Sa = sa;
    }

    public String getSb() {
        return Sb;
    }

    public void setSb(String sb) {
        Sb = sb;
    }

    public String getKa() {
        return Ka;
    }

    public void setKa(String ka) {
        Ka = ka;
    }

    public String getKb() {
        return Kb;
    }

    public void setKb(String kb) {
        Kb = kb;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
