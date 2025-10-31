package Console_Project;

import java.util.*;

class Account {
    private static int counter = 1000;
    private int accountNumber;
    private String name;
    private double balance;

    public Account(String name, double initialDeposit) {
        this.accountNumber = counter++;
        this.name = name;
        this.balance = initialDeposit;
    }

    public int getAccountNumber() { return accountNumber; }
    public String getName() { return name; }
    public double getBalance() { return balance; }

    public void deposit(double amount) {
        if (amount > 0) balance += amount;
    }

    public boolean withdraw(double amount) {
        if (amount > 0 && amount <= balance) {
            balance -= amount;
            return true;
        }
        return false;
    }

    public void display() {
        System.out.println("Account No: " + accountNumber);
        System.out.println("Name: " + name);
        System.out.println("Balance: ₹" + balance);
    }
}

public class BankingSystem {
    static Scanner sc = new Scanner(System.in);
    static List<Account> accounts = new ArrayList<>();

    public static void main(String[] args) {
        while (true) {
            System.out.println("\n--- Banking System ---");
            System.out.println("1. Create Account\n2. Deposit\n3. Withdraw\n4. View Account\n5. Exit");
            System.out.print("Choose: ");
            int choice = sc.nextInt();

            switch (choice) {
                case 1 -> createAccount();
                case 2 -> deposit();
                case 3 -> withdraw();
                case 4 -> viewAccount();
                case 5 -> System.exit(0);
                default -> System.out.println("Invalid choice!");
            }
        }
    }

    static void createAccount() {
        sc.nextLine(); // consume newline
        System.out.print("Enter name: ");
        String name = sc.nextLine();
        System.out.print("Initial deposit: ₹");
        double deposit = sc.nextDouble();
        Account acc = new Account(name, deposit);
        accounts.add(acc);
        System.out.println("Account created. Account No: " + acc.getAccountNumber());
    }

    static Account findAccount(int accNo) {
        for (Account acc : accounts) {
            if (acc.getAccountNumber() == accNo) return acc;
        }
        return null;
    }

    static void deposit() {
        System.out.print("Enter account number: ");
        int accNo = sc.nextInt();
        Account acc = findAccount(accNo);
        if (acc != null) {
            System.out.print("Enter amount to deposit: ₹");
            double amount = sc.nextDouble();
            acc.deposit(amount);
            System.out.println("Deposit successful.");
        } else {
            System.out.println("Account not found.");
        }
    }

    static void withdraw() {
        System.out.print("Enter account number: ");
        int accNo = sc.nextInt();
        Account acc = findAccount(accNo);
        if (acc != null) {
            System.out.print("Enter amount to withdraw: ₹");
            double amount = sc.nextDouble();
            if (acc.withdraw(amount)) {
                System.out.println("Withdrawal successful.");
            } else {
                System.out.println("Insufficient balance or invalid amount.");
            }
        } else {
            System.out.println("Account not found.");
        }
    }

    static void viewAccount() {
        System.out.print("Enter account number: ");
        int accNo = sc.nextInt();
        Account acc = findAccount(accNo);
        if (acc != null) {
            acc.display();
        } else {
            System.out.println("Account not found.");
        }
    }
}
