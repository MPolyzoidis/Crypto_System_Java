import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;


public class Assymetrical {
    private static KeyPair keyPair = null;

    public static void run() throws Exception {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        if (Files.exists(Paths.get("public_key.pem")) && Files.exists(Paths.get("private_key.pem"))) {
            try {
                PublicKey publicKey = readPublicKeyFromFile("public_key.pem");
                PrivateKey privateKey = readPrivateKeyFromFile("private_key.pem");
                if (publicKey != null && privateKey != null) {
                    keyPair = new KeyPair(publicKey, privateKey);
                    System.out.println("Using existing key pair created from a previous runtime.");
                }
            } catch (Exception e) {
                System.out.println("Failed to load key pair from existing files: " + e.getMessage());
            }
        }

        while (!exit) {
            System.out.println("\nChoose an option:");
            System.out.println("1. Create/Change Key");
            System.out.println("2. Encrypt Message");
            System.out.println("3. Decrypt Message");
            System.out.println("4. Exit");

            int choice = scanner.nextInt();
            scanner.nextLine(); 

            switch (choice) {
                case 1:
                    createKey(scanner);
                    break;
                case 2:
                    if (keyPair == null) {
                        System.out.println("Please create a key first.");
                        break;
                    }
                    encryptMessage(scanner);
                    break;
                case 3:
                    if (keyPair == null) {
                        System.out.println("Please create a key first.");
                        break;
                    }
                    decryptMessage(scanner);
                    break;
                case 4:
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
        System.out.println("1. 1024 bits");
        System.out.println("2. 2048 bits");
        System.out.println("3. 4096 bits");
        int sizeChoice = scanner.nextInt();
        int keySize;
        switch (sizeChoice) {
            case 1:
                keySize = 1024;
                break;
            case 2:
                keySize = 2048;
                break;
            case 3:
                keySize = 4096;
                break;
            default:
                System.out.println("Invalid choice, using default key size (2048 bits).");
                keySize = 2048;
        }
        scanner.nextLine();
        String randomnessSource = selectRandomnessSource(scanner);

        keyPair = generateKeyPair(keySize, randomnessSource);
        if (keyPair != null) {
            System.out.println("Key pair created successfully.");
            try {
                saveKeyToFile("public_key.pem", keyPair.getPublic());
                saveKeyToFile("private_key.pem", keyPair.getPrivate());
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Failed to create key pair.");
        }
    }

    private static String selectRandomnessSource(Scanner scanner) {
        System.out.println("Select randomness source:");
        System.out.println("1. SHA1PRNG");
        System.out.println("2. Default");
        System.out.println("3. Windows-PRNG");
        int choice = scanner.nextInt();
        scanner.nextLine(); 
        switch (choice) {
            case 1:
                return "SHA1PRNG";
            case 2:
                return "DEFAULT";
            case 3:
                return "Windows-PRNG";
            default:
                System.out.println("Invalid choice, using default (SHA1PRNG).");
                return "SHA1PRNG";
        }
    }

    private static KeyPair generateKeyPair(int keySize, String randomnessSource) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            SecureRandom secureRandom;
            if ("DEFAULT".equals(randomnessSource)) {
                secureRandom = new SecureRandom();
            } else {
                secureRandom = SecureRandom.getInstance(randomnessSource);
            }
            keyPairGenerator.initialize(keySize, secureRandom);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Error generating key pair: " + e.getMessage());
            return null;
        }
    }

    private static void encryptMessage(Scanner scanner) throws Exception {
        if (keyPair == null) {
            System.out.println("Please create a key first.");
            return;
        }

        System.out.println("Choose an option:");
        System.out.println("1. Enter plaintext directly");
        System.out.println("2. Upload plaintext from a file");

        int option = scanner.nextInt();
        scanner.nextLine();

        String plaintext;

        switch (option) {
            case 1:
                System.out.print("Enter plaintext to encrypt: ");
                plaintext = scanner.nextLine();
                break;
            case 2:
                System.out.print("Enter the path of the file containing the plaintext: ");
                String filePath = scanner.nextLine();
                plaintext = new String(Files.readAllBytes(Paths.get(filePath)));
                break;
            default:
                System.out.println("Invalid option. Using direct input.");
                System.out.print("Enter plaintext to encrypt: ");
                plaintext = scanner.nextLine();
                break;
        }

        byte[] encryptedBytes = encrypt(plaintext, keyPair.getPublic());
        System.out.println("Encrypted text (Hex): " + bytesToHex(encryptedBytes));
    }

    private static void decryptMessage(Scanner scanner) throws Exception {
        if (keyPair == null) {
            System.out.println("Please create a key first.");
            return;
        }

        System.out.print("Enter encrypted text in hexadecimal format: ");
        String hexInput = scanner.nextLine();
        byte[] encryptedBytes = hexStringToByteArray(hexInput);

        System.out.print("Enter private key file path: ");
        String privateKeyPath = scanner.nextLine();

        PrivateKey privateKey = readPrivateKeyFromFile(privateKeyPath);

        String decryptedText = decrypt(encryptedBytes, privateKey);
        System.out.println("Decrypted text: " + decryptedText);
    }

    private static byte[] encrypt(String plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext.getBytes());
    }

    private static String decrypt(byte[] encryptedBytes, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
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

    private static void saveKeyToFile(String fileName, Key key) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(keyToPEM(key).getBytes());
        }
    }

    private static String keyToPEM(Key key) {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN ").append(key instanceof RSAPrivateKey ? "RSA PRIVATE" : "PUBLIC").append(" KEY-----\n");
        pem.append(Base64.getEncoder().encodeToString(key.getEncoded())).append("\n");
        pem.append("-----END ").append(key instanceof RSAPrivateKey ? "RSA PRIVATE" : "PUBLIC").append(" KEY-----\n");
        return pem.toString();
    }

    private static PublicKey readPublicKeyFromFile(String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        String keyString = new String(keyBytes);

        keyString = keyString.replace("-----BEGIN PUBLIC KEY-----", "");
        keyString = keyString.replace("-----END PUBLIC KEY-----", "");
        keyString = keyString.replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(keyString);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey readPrivateKeyFromFile(String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        String keyString = new String(keyBytes);

        keyString = keyString.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        keyString = keyString.replace("-----END RSA PRIVATE KEY-----", "");
        keyString = keyString.replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(keyString);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
    }
}
