import java.util.List;
public class Sample {
    public static final int CONST = 42;
    private static String greeting = "hello";
    private int counter;
    public Sample(int c) { counter = c; }
    public int add(int a, int b) { return a + b; }
    public int switcher(int x) {
        switch (x) { case 1: return 10; case 2: return 20; default: return -1; }
    }
    public int loopy(int n) { int s = 0; for (int i = 0; i < n; i++) s += i; return s; }
    public void trier(int[] xs) {
        try { System.out.println(xs[0]); } catch (NullPointerException | ArrayIndexOutOfBoundsException e) { e.printStackTrace(); }
    }
    public <T> T generic(T t) { return t; }
    public void varargs(String... xs) { for (String s : xs) greeting = s; }
    @Override public String toString() { return "Sample:" + counter; }
    interface Iface { int f(); }
    static class Impl implements Iface { public int f() { return CONST; } }
    public Runnable mk() { return () -> System.out.println(greeting); }
}
