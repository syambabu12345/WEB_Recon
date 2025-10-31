package Console_Project;

import java.util.*;

public class First_console_Project {
    static class Task {
        String description;
        boolean isDone;

        Task(String description) {
            this.description = description;
            this.isDone = false;
        }

        public String toString() {
            return (isDone ? "[✔] " : "[ ] ") + description;
        }
    }

    static List<Task> tasks = new ArrayList<>();
    static Scanner sc = new Scanner(System.in);

    public static void main(String[] args) {
        while (true) {
            System.out.println("\n--- To-Do List ---");
            System.out.println("1. Add Task\n2. View Tasks\n3. Mark Done\n4. Delete Task\n5. Exit");
            System.out.print("Choose: ");
            int choice = sc.nextInt();
            sc.nextLine(); // consume newline

            switch (choice) {
                case 1 -> addTask();
                case 2 -> viewTasks();
                case 3 -> markDone();
                case 4 -> deleteTask();
                case 5 -> System.exit(0);
                default -> System.out.println("Invalid choice!");
            }
        }
    }

    static void addTask() {
        System.out.print("Enter task: ");
        String desc = sc.nextLine();
        tasks.add(new Task(desc));
        System.out.println("Task added.");
    }

    static void viewTasks() {
        if (tasks.isEmpty()) {
            System.out.println("No tasks yet.");
            return;
        }
        for (int i = 0; i < tasks.size(); i++) {
            System.out.println((i + 1) + ". " + tasks.get(i));
        }
    }

    static void markDone() {
        viewTasks();
        System.out.print("Enter task number to mark done: ");
        int index = sc.nextInt() - 1;
        if (index >= 0 && index < tasks.size()) {
            tasks.get(index).isDone = true;
            System.out.println("Task marked as done.");
        } else {
            System.out.println("Invalid task number.");
        }
    }

    static void deleteTask() {
        viewTasks();
        System.out.print("Enter task number to delete: ");
        int index = sc.nextInt() - 1;
        if (index >= 0 && index < tasks.size()) {
            tasks.remove(index);
            System.out.println("Task deleted.");
        } else {
            System.out.println("Invalid task number.");
        }
    }
}
