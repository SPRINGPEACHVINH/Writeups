package c.b.a;

public class Main {
    public static void main(String[] args) {
        try {
            // Tạo đối tượng của class b và g
            b decryptionClass = new b();
            g generationClass = new g();

            // Gọi g.a() để tạo chuỗi
            String generatedString = generationClass.a();
            System.out.println("Generated String from g.a(): " + generatedString);

            // Gọi b.a(g.a()) để giải mã
            String decryptedResult = decryptionClass.a(generatedString);
            System.out.println("Decrypted Result from b.a(g.a()): " + decryptedResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}