import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class bruteforce {

    // Target hash from the original code
    private static final String TARGET_HASH = "a2a3d412e92d896134d9c9126d756f";

    public static void main(String[] args) {
        System.out.println("Reading password list from rockyou.txt...");
        try (BufferedReader reader = new BufferedReader(new FileReader("rockyou.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                checkPassword(line.trim());
            }
            System.out.println("Finished - password not found!");
        } catch (IOException e) {
            System.err.println("Unable to read file rockyou.txt: " + e.getMessage());
        }
    }

    // Check password
    private static void checkPassword(String candidate) {
        try {
            String hash = customMD5(candidate);
            if (hash.equals(TARGET_HASH)) {
                System.out.println("\n✅ PASSWORD FOUND: " + candidate);
                System.exit(0);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // MD5 hashing function similar to the original code
    private static String customMD5(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(input.getBytes());

        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(Integer.toHexString(b & 0xFF));
        }
        return sb.toString();
    }
}
