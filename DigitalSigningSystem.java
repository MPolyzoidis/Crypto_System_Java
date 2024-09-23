import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class DigitalSigningSystem {
    private static KeyPair keyPair = null;

    public static void run() throws Exception {
        Scanner scanner = new Scanner(System.in);
        boolean exit = false;

        // Check for existing keys
        if (Files.exists(Paths.get("public_dsa_key.pem")) && Files.exists(Paths.get("private_dsa_key.pem"))) {
            try {
                PublicKey publicKey = readPublicKeyFromFile("public_dsa_key.pem");
                PrivateKey privateKey = readPrivateKeyFromFile("private_dsa_key.pem");
                if (publicKey != null && privateKey != null) {
                    keyPair = new KeyPair(publicKey, privateKey);
                    System.out.println("Using existing DSA key pair created from a previous runtime.");
                }
            } catch (Exception e) {
                System.out.println("Failed to load DSA key pair from existing files: " + e.getMessage());
            }
        }

        while (!exit) {
            System.out.println("\nChoose an option:");
            System.out.println("1. Create/Change Key");
            System.out.println("2. Sign Data");
            System.out.println("3. Verify Signature");
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
                    signData(scanner);
                    break;
                case 3:
                    if (keyPair == null) {
                        System.out.println("Please create a key first.");
                        break;
                    }
                    verifySignature(scanner);
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
        int sizeChoice = scanner.nextInt();
        int keySize;
        switch (sizeChoice) {
            case 1:
                keySize = 1024;
                break;
            case 2:
                keySize = 2048;
                break;
            default:
                System.out.println("Invalid choice, using default key size (2048 bits).");
                keySize = 2048;
        }
        scanner.nextLine();
        String randomnessSource = selectRandomnessSource(scanner);

        keyPair = generateKeyPair(keySize, randomnessSource);
        if (keyPair != null) {
            System.out.println("DSA key pair created successfully.");
            try {
                saveKeyToFile("public_dsa_key.pem", keyPair.getPublic());
                saveKeyToFile("private_dsa_key.pem", keyPair.getPrivate());
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("Failed to create DSA key pair.");
        }
    }

    private static String selectRandomnessSource(Scanner scanner) {
        System.out.println("Select randomness source:");
        System.out.println("1. SHA1PRNG");
        System.out.println("2. Default");
        System.out.println("3. DRBG");
        int choice = scanner.nextInt();
        scanner.nextLine();
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

    private static KeyPair generateKeyPair(int keySize, String randomnessSource) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            SecureRandom secureRandom;
            switch (randomnessSource) {
                case "DEFAULT":
                    secureRandom = new SecureRandom();
                    break;
                case "DRBG":
                    secureRandom = SecureRandom.getInstance("DRBG");
                    break;
                default:
                    secureRandom = SecureRandom.getInstance(randomnessSource);
                    break;
            }
            keyPairGenerator.initialize(keySize, secureRandom);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            System.out.println("Error generating key pair: " + e.getMessage());
            return null;
        }
    }

    private static void signData(Scanner scanner) throws Exception {
        System.out.println("Choose an option:");
        System.out.println("1. Enter data directly");
        System.out.println("2. Upload data from a file");

        int option = scanner.nextInt();
        scanner.nextLine();

        String data;

        switch (option) {
            case 1:
                System.out.print("Enter data to sign: ");
                data = scanner.nextLine();
                break;
            case 2:
                System.out.print("Enter the path of the file containing the data: ");
                String filePath = scanner.nextLine();
                data = new String(Files.readAllBytes(Paths.get(filePath)));
                break;
            default:
                System.out.println("Invalid option. Using direct input.");
                System.out.print("Enter data to sign: ");
                data = scanner.nextLine();
                break;
        }

        byte[] signature = sign(data, keyPair.getPrivate());
        String signatureBase64 = Base64.getEncoder().encodeToString(signature);
        System.out.println("Signature (Base64): " + signatureBase64);
        saveSignatureToFile("signature.dat", signature);
        saveDataToTxtFile("signed_data.txt", data);
    }

    private static void saveDataToTxtFile(String fileName, String data) {
        try (FileWriter writer = new FileWriter(fileName)) {
            writer.write(data);
        } catch (IOException e) {
            System.out.println("Error writing to file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void verifySignature(Scanner scanner) throws Exception {
        System.out.print("Enter the path of the file containing the data: ");
        String filePath = scanner.nextLine();
        String data = new String(Files.readAllBytes(Paths.get(filePath)));

        System.out.print("Enter the path of the file containing the signature: ");
        String signaturePath = scanner.nextLine();
        byte[] signatureBytes = Files.readAllBytes(Paths.get(signaturePath));
        String signatureBase64 = new String(signatureBytes);
        System.out.println("Read Signature (Base64): " + signatureBase64);  // Print the read signature
        byte[] signature = Base64.getDecoder().decode(signatureBase64);  // Decode the Base64 signature

        boolean isVerified = verify(data, signature, keyPair.getPublic());
        System.out.println("Signature verification result: " + isVerified);
    }

    private static byte[] sign(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        return signature.sign();
    }

    private static boolean verify(String data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initVerify(publicKey);
        signature.update(data.getBytes());
        return signature.verify(signatureBytes);
    }

    private static void saveSignatureToFile(String fileName, byte[] signature) throws Exception {
        String encodedSignature = Base64.getEncoder().encodeToString(signature);
        System.out.println("Encoded Signature (Base64): " + encodedSignature);  // Print the encoded signature
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(encodedSignature.getBytes());  // Save as Base64 encoded string
        }
    }

    private static void saveKeyToFile(String fileName, Key key) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(keyToPEM(key).getBytes());
        }
    }

    private static String keyToPEM(Key key) {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN ").append(key instanceof PrivateKey ? "PRIVATE" : "PUBLIC").append(" KEY-----\n");
        pem.append(Base64.getEncoder().encodeToString(key.getEncoded())).append("\n");
        pem.append("-----END ").append(key instanceof PrivateKey ? "PRIVATE" : "PUBLIC").append(" KEY-----\n");
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
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");

        return keyFactory.generatePublic(keySpec);
    }

    private static PrivateKey readPrivateKeyFromFile(String fileName) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
        String keyString = new String(keyBytes);

        keyString = keyString.replace("-----BEGIN PRIVATE KEY-----", "");
        keyString = keyString.replace("-----END PRIVATE KEY-----", "");
        keyString = keyString.replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(keyString);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");

        return keyFactory.generatePrivate(keySpec);
    }

    public static void main(String[] args) throws Exception {
        run();
    }
}
