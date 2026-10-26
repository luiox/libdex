import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 覆盖注解族与静态初值编码的样本：运行时/构建时可见性、数组与枚举载荷。 */
public class Annotated {
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.FIELD, ElementType.METHOD})
    public @interface Marker {
        String tag() default "t";
        int[] ids() default {1, 2};
        Phase phase() default Phase.ONE;
    }

    public enum Phase { ONE, TWO }

    public static final boolean B = true;
    public static final byte BY = -5;
    public static final short S = 300;
    public static final char C = 'x';
    public static final int I = 100000;
    public static final long L = 0x1234567890L;
    public static final float F = 1.5f;
    public static final double D = 2.75;
    public static final String STR = "value";
    public static final Phase P = Phase.TWO;
    public static final int TAIL_DEFAULT = 0;  // 尾部默认值，规范允许省略槽位

    @Marker(tag = "field", ids = {7, 8, 9}, phase = Phase.TWO)
    public int annotated;

    @Marker(tag = "method")
    public int combine(int a) {
        return a + annotated;
    }

    @Override
    public String toString() {
        return STR + B + S + C + I + L + F + D + P + TAIL_DEFAULT;
    }
}
