package site.aicc.sm2.keygen;

import site.aicc.sm2.ec.AbstractECPoint;
//@formatter:off
/**
* <ul>
*     <li>
*       <h3>类功能概述：</h3>
*       <p>本类用于(For) : SM2 公钥</p>
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
*           <li>Date : 2020-09-26 | 下午07:57:38</li>
*          
*           <li>History : 新建类.</li>
*       </ul>
*     </li>
*     
*     
* </ul>
*/
//@formatter:on
public class ECPublicKey extends ECKey {

    private final AbstractECPoint Q;

    public ECPublicKey(AbstractECPoint Q) {
        super(false);
        this.Q = validate(Q);
    }

    private AbstractECPoint validate(AbstractECPoint q) {
        if (q == null) {
            throw new IllegalArgumentException("该点为NULL");
        }
        if (q.isInfinity()) {
            throw new IllegalArgumentException("该点是无穷远点");
        }
        if (!q.isValid()) {
            throw new IllegalArgumentException("点不在椭圆上");
        }
        return q;
    }

    public AbstractECPoint getQ() {
        return Q;
    }
}
