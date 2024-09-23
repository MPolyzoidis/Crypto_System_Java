import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class Symmetrical {
    private static String key = null; // Holds the current key
    private static int keySize = 128; // Default key size
    private static final String KEYSTORE_PATH = "keystore.p12";
    private static final String SECRET_KEY_ALIAS = "secretKeyAlias";

    public static void run() throws Exception {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        while (!exit) {
            System.out.println("\nChoose an option:");
            System.out.println("1. Create/Change Key");
            System.out.println("2. Encrypt Message");
            System.out.println("3. Decrypt Message");
            System.out.println("4. View Stored Key");
            System.out.println("5. Exit");

            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline character

            switch (choice) {
                case 1:
                    createKey(scanner);
                    break;
                case 2:
                    if (key == null) {
                        System.out.println("Please create a key first.");
                    } else {
                        encryptMessage(scanner);
                    }
                    break;
                case 3:
                    if (key == null) {
                        System.out.println("Please create a key first.");
                    } else {
                        decryptMessage(scanner);
                    }
                    break;
                case 4:
                    if (key == null) {
                        System.out.println("Please create a key first.");
                    } else {
                        if (showKey(scanner)) {
                            System.out.println("Key stored is " + key);
                        }
                    }
                    break;
                case 5:
                    throw new ReturnToMainMenuException();
                default:
                    System.out.println("Invalid option. Please choose again.");
            }
        }
        scanner.close();
    }

    private static void createKey(Scanner scanner) {
        System.out.println("Creating/Changing Key...");
        System.out.println("Choose key size:");
        System.out.println("1. 128 bits");
        System.out.println("2. 192 bits");
        System.out.println("3. 256 bits");
        int sizeChoice = scanner.nextInt();
        switch (sizeChoice) {
            case 1:
                keySize = 128;
                break;
            case 2:
                keySize = 192;
                break;
            case 3:
                keySize = 256;
                break;
            default:
                System.out.println("Invalid choice, using default key size (128 bits).");
        }
        scanner.nextLine(); // Consume newline character

        System.out.print("Enter password to protect the key: ");
        char[] password = scanner.nextLine().toCharArray();

        String randomnessSource = selectRandomnessSource(scanner);
        key = generateRandomKey(keySize, randomnessSource);

        if (key == null || key.isEmpty()) {
            System.out.println("Error generating key, please try again.");
            return;
        }

        // Store the key in the keystore
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            File keystoreFile = new File(KEYSTORE_PATH);

            // If the keystore file exists, delete it to avoid integrity issues
            if (keystoreFile.exists()) {
                keystoreFile.delete();
            }

            ks.load(null, password); // Initialize a new keystore

            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
            KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
            ks.setEntry(SECRET_KEY_ALIAS, skEntry, protParam);

            try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
                ks.store(fos, password);
            }

            System.out.println("Key created/changed and stored successfully.");
        } catch (Exception e) {
            System.out.println("Error storing key in keystore: " + e.getMessage());
            e.printStackTrace();  // Print stack trace for detailed error information
        }
    }

    private static String selectRandomnessSource(Scanner scanner) {
        System.out.println("Select randomness source:");
        System.out.println("1. SHA1PRNG");
        System.out.println("2. Default");
        System.out.println("3. DRBG");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline character
        switch (choice) {
            case 1:
                return "SHA1PRNG";
            case 2:
                return "DEFAULT";
            case 3:
                return "DRBG";
            default:
                System.out.println("Invalid choice, using default (SHA1PRNG).");
                return "SHA1PRNG";
        }
    }

    private static void encryptMessage(Scanner scanner) throws Exception {
        System.out.println("Choose an option:");
        System.out.println("1. Enter plaintext to encrypt");
        System.out.println("2. Encrypt text from a file");

        int option = scanner.nextInt();
        scanner.nextLine(); // Consume newline character

        switch (option) {
            case 1:
                System.out.print("Enter plaintext to encrypt: ");
                String plaintext = scanner.nextLine();
                performEncryption(plaintext);
                break;
            case 2:
                System.out.print("Enter the path to the file containing plaintext: ");
                String filePath = scanner.nextLine();
                String fileContent = readFile(filePath);
                performEncryption(fileContent);
                break;
            default:
                System.out.println("Invalid option.");
                break;
        }
    }

    private static String readFile(String filePath) throws IOException {
        StringBuilder contentBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                contentBuilder.append(line).append("\n");
            }
        }
        return contentBuilder.toString();
    }

    private static void performEncryption(String plaintext) throws Exception {
        // Generate a random IV of 16 characters (128 bits)
        String iv = generateRandomIV();

        // Encrypt the plaintext
        byte[] encryptedBytes = encrypt(plaintext, key, iv);

        // Print the encrypted text in hexadecimal format
        System.out.print("Encrypted text (Hex): ");
        for (byte b : encryptedBytes) {
            System.out.printf("%02X", b);
        }
        System.out.println();

        // Print the IV
        System.out.println("IV: " + iv);
    }

    private static void decryptMessage(Scanner scanner) throws Exception {
        System.out.println("Enter encrypted text in hexadecimal format: ");
        String hexInput = scanner.nextLine();
        byte[] encryptedBytes = hexStringToByteArray(hexInput);

        System.out.println("Enter IV: ");
        String iv = scanner.nextLine();

        System.out.println("Choose an option:");
        System.out.println("1. Enter secret key manually");

        int option = scanner.nextInt();
        scanner.nextLine(); // Consume newline character

        String secretKey = null;
        switch (option) {
            case 1:
                System.out.print("Enter secret key: ");
                secretKey = scanner.nextLine();
                break;
            case 2:
                System.out.print("Enter the path to the secretKey.txt file: ");
                String keyFilePath = scanner.nextLine();
                try {
                    secretKey = new String(Files.readAllBytes(Paths.get(keyFilePath)));
                } catch (IOException e) {
                    System.out.println("Error reading secretKey.txt file: " + e.getMessage());
                }
                break;
            default:
                System.out.println("Invalid option.");
                return;
        }

        if (secretKey != null) {
            // Decrypt the ciphertext
            String decryptedText = decrypt(encryptedBytes, secretKey, iv);
            System.out.println("Decrypted text: " + decryptedText);
        }
    }

    private static byte[] encrypt(String plaintext, String key, String iv) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plaintext.getBytes());
    }

    private static String decrypt(byte[] encryptedBytes, String key, String iv) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    private static String generateRandomKey(int keySize, String randomnessSource) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder stringBuilder = new StringBuilder();
        SecureRandom random;
        try {
            switch (randomnessSource) {
                case "DEFAULT":
                    random = new SecureRandom();
                    break;
                case "DRBG":
                    random = SecureRandom.getInstance("DRBG");
                    break;
                default:
                    random = SecureRandom.getInstance(randomnessSource);
                    break;
            }
            for (int i = 0; i < keySize / 8; i++) {
                int index = random.nextInt(chars.length());
                stringBuilder.append(chars.charAt(index));
            }
        } catch (Exception e) {
            System.out.println("Error generating random key: " + e.getMessage());
            e.printStackTrace();  // Print stack trace for detailed error information
            return null;
        }
        return stringBuilder.toString();
    }

    private static String generateRandomIV() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder stringBuilder = new StringBuilder();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 16; i++) {
            int index = random.nextInt(chars.length());
            stringBuilder.append(chars.charAt(index));
        }
        return stringBuilder.toString();
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static boolean showKey(Scanner scanner) {
        System.out.println("Enter password to show key:");
        char[] password = scanner.nextLine().toCharArray();

        // Load the key from the keystore
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            File keystoreFile = new File(KEYSTORE_PATH);
            if (keystoreFile.exists()) {
                try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                    ks.load(fis, password);
                }

                KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
                KeyStore.SecretKeyEntry skEntry = (KeyStore.SecretKeyEntry) ks.getEntry(SECRET_KEY_ALIAS, protParam);
                SecretKey secretKey = skEntry.getSecretKey();
                key = new String(secretKey.getEncoded());
                return true;
            } else {
                System.out.println("Keystore not found.");
                return false;
            }
        } catch (Exception e) {
            System.out.println("Error loading key from keystore: " + e.getMessage());
            e.printStackTrace();  // Print stack trace for detailed error information
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        run();
    }
}
