import java.util.InputMismatchException;
import java.util.NoSuchElementException;
import java.util.Scanner;

public class MainMenu {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            try {
                System.out.println("\nPlease choose an option:");
                System.out.println("1. Symmetrical");
                System.out.println("2. Assymetrical");
                System.out.println("3. Digital Signing System");
                System.out.println("4. Exit");

                int choice = scanner.nextInt();

                switch (choice) {
                    case 1:
                    try {
                        Symmetrical.run();
                    } catch (ReturnToMainMenuException e) {
                        System.out.println(e.getMessage());
                    } catch (Exception e) {
                        System.out.println("Error running Symmetrical: " + e.getMessage());
                    }
                    break;
                    case 2:
                        try {
                            Assymetrical.run();
                        } catch (ReturnToMainMenuException e) {
                            System.out.println(e.getMessage());
                        } catch (Exception e) {
                            System.out.println("Error running Symmetrical: " + e.getMessage());
                        }
                        break;
                    case 3:
                        try {
                            DigitalSigningSystem.run();
                        } catch (ReturnToMainMenuException e) {
                            System.out.println(e.getMessage());
                        } catch (Exception e) {
                            System.out.println("Error running Symmetrical: " + e.getMessage());
                        }
                        break;
                    case 4:
                        System.out.println("Exiting the program.");
                        scanner.close();
                        System.exit(0);
                    default:
                        System.out.println("Invalid choice. Please choose again.");
                }
            } catch (InputMismatchException e) {
                System.out.println("Invalid input. Please enter a number.");
                scanner.next(); // Clear the invalid input
            } catch (NoSuchElementException e) {
                System.out.println("No input available. Exiting the program.");
                System.exit(1);
            }
        }
    }
}


