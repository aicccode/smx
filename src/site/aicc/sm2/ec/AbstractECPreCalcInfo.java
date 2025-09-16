package site.aicc.sm2.ec;
//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : 倍点运算器预计算信息</p>
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
*           <li>Date : 2020-09-26 | 下午10:42:57</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
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
