#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#define MAX_USERS 10
#define USERNAME_LENGTH 20
#define PASSWORD_LENGTH (SHA256_DIGEST_LENGTH * 2) // Twice the length of SHA256 hash in hexadecimal
#define MAX_LOGIN_ATTEMPTS 3

typedef struct {
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH + 1]; // Additional space for null terminator
    char mfa_code[7]; // Six-digit MFA code + null terminator
} User;

User users[MAX_USERS];
int num_users = 0;

void save_users_to_file(const char *filename); // Function prototype
void read_mfa_code(char *mfa_input); // Function prototype
void read_password(char *password); // Function prototype

void register_user(const char *username, const char *password, const char *mfa_code) {
    if (num_users >= MAX_USERS) {
        printf("Maximum number of users reached.\n");
        return;
    }

    if (strlen(username) >= USERNAME_LENGTH || strlen(password) >= PASSWORD_LENGTH || strlen(mfa_code) != 6) {
        printf("Invalid input.\n");
        return;
    }

    // Hash the password using SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit(mdctx, EVP_sha256());
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal(mdctx, hash, NULL);
    EVP_MD_CTX_free(mdctx);

    // Convert the hash to a hexadecimal string
    char hex_hash[PASSWORD_LENGTH + 1]; // Additional space for null terminator
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hex_hash[i * 2], "%02x", hash[i]);
    }

    strcpy(users[num_users].username, username);
    strcpy(users[num_users].password, hex_hash);
    strcpy(users[num_users].mfa_code, mfa_code);
    num_users++;

    save_users_to_file("users.txt"); // Save user data to file after registration
}

void save_users_to_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    for (int i = 0; i < num_users; i++) {
        fprintf(file, "%s %s %s\n", users[i].username, users[i].password, users[i].mfa_code);
    }

    fclose(file);
}

void load_users_from_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    while (fscanf(file, "%s %s %s", users[num_users].username, users[num_users].password, users[num_users].mfa_code) == 3) {
        num_users++;
        if (num_users >= MAX_USERS) {
            break;
        }
    }

    fclose(file);
}

int login(const char *username, const char *password) {
    int attempts_left = MAX_LOGIN_ATTEMPTS;
    while (attempts_left > 0) {
        for (int i = 0; i < num_users; i++) {
            if (strcmp(users[i].username, username) == 0) {
                // Hash the input password using SHA-256
                unsigned char input_hash[SHA256_DIGEST_LENGTH];
                EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
                EVP_DigestInit(mdctx, EVP_sha256());
                EVP_DigestUpdate(mdctx, password, strlen(password));
                EVP_DigestFinal(mdctx, input_hash, NULL);
                EVP_MD_CTX_free(mdctx);

                // Convert the hash to a hexadecimal string
                char input_hex_hash[PASSWORD_LENGTH + 1]; // Additional space for null terminator
                for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
                    sprintf(&input_hex_hash[j * 2], "%02x", input_hash[j]);
                }

                // Compare the hashes
                if (strcmp(users[i].password, input_hex_hash) == 0) {
                    // Prompt for MFA code
                    char mfa_input[7];
                    printf("Enter your 6-digit MFA code: ");
                    fflush(stdout); // Flush the output buffer to ensure prompt is displayed
                    read_mfa_code(mfa_input);
                    
                    // Compare MFA code
                    if (strcmp(users[i].mfa_code, mfa_input) == 0) {
                        printf("Login successful.\n");
                        return 1;
                    } else {
                        printf("Incorrect MFA code.\n");
                        attempts_left--;
                        if (attempts_left > 0) {
                            printf("Attempts left: %d\n", attempts_left);
                            printf("Please try again.\n");
                        } else {
                            printf("Max login attempts reached. Account locked.\n");
                            return 0;
                        }
                    }
                } else {
                    attempts_left--;
                    if (attempts_left > 0) {
                        printf("Incorrect password. Attempts left: %d\n", attempts_left);
                        printf("Please try again.\n");
                    } else {
                        printf("Max login attempts reached. Account locked.\n");
                        return 0;
                    }
                }
            }
        }
        printf("User not found.\n");
        return 0;
    }
}

void read_mfa_code(char *mfa_input) {
#ifdef _WIN32
    int i = 0;
    while (1) {
        char ch = getch();
        if (ch == '\r' || ch == '\n') {
            mfa_input[i] = '\0';
            putchar('\n');
            break;
        } else if (ch == '\b' && i > 0) {
            printf("\b \b"); // Move cursor back, overwrite the character with space, move cursor back again
            i--;
        } else if (i < 6 && isdigit(ch)) {
            putchar(ch); // Print digit instead of asterisk
            mfa_input[i] = ch;
            i++;
        }
    }
#else
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON); // Turn off echo and canonical mode
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    int i = 0;
    while (1) {
        char ch;
        read(STDIN_FILENO, &ch, sizeof(ch));
        if (ch == '\n') {
            mfa_input[i] = '\0';
            putchar('\n');
            break;
        } else if (ch == 127 && i > 0) {
            printf("\b \b"); // Move cursor back, overwrite the character with space, move cursor back again
            i--;
        } else if (i < 6 && isdigit(ch)) {
            putchar(ch); // Print digit instead of asterisk
            mfa_input[i] = ch;
            i++;
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term); // Restore old terminal settings
#endif
}

void read_password(char *password) {
#ifdef _WIN32
    int i = 0;
    while (1) {
        char ch = getch();
        if (ch == '\r' || ch == '\n') {
            password[i] = '\0';
            putchar('\n');
            break;
        } else if (ch == '\b' && i > 0) {
            printf("\b \b"); // Move cursor back, overwrite the character with space, move cursor back again
            i--;
        } else if (i < PASSWORD_LENGTH && ch != '\b') { // Ignore backspace when at beginning
            putchar(ch); // Print character instead of asterisk
            password[i] = ch;
            i++;
        }
    }
#else
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON); // Turn off echo and canonical mode
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    int i = 0;
    while (1) {
        char ch;
        read(STDIN_FILENO, &ch, sizeof(ch));
        if (ch == '\n') {
            password[i] = '\0';
            putchar('\n');
            break;
        } else if (ch == 127 && i > 0) {
            printf("\b \b"); // Move cursor back, overwrite the character with space, move cursor back again
            i--;
        } else if (i < PASSWORD_LENGTH && ch != 127) { // Ignore backspace when at beginning
            putchar(ch); // Print character instead of asterisk
            password[i] = ch;
            i++;
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term); // Restore old terminal settings
#endif
}

int main() {
    int choice;
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH];
    char mfa_code[7];
    int attempts;

    load_users_from_file("users.txt");

    while (1) {
        printf("1. Login\n");
        printf("2. Register\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                attempts = MAX_LOGIN_ATTEMPTS;
                while (attempts > 0) {
                    printf("Enter username: ");
                    scanf("%s", username);
                    printf("Enter password: ");
                    read_password(password);
                    if (login(username, password)) {
                        break;
                    } else {
                        attempts--;
                        if (attempts > 0) {
                            printf("Please try again. Attempts left: %d\n", attempts);
                        } else {
                            printf("Max login attempts reached. Account locked.\n");
                            break;
                        }
                    }
                }
                break;
            case 2:
                printf("Enter username: ");
                scanf("%s", username);
                printf("Enter password: ");
                read_password(password);
                printf("Enter 6-digit multi-factor authentication code (MFA): ");
                read_mfa_code(mfa_code);
                register_user(username, password, mfa_code);
                printf("\nUser registered successfully.\n"); // Print User registered successfully in the next line
                break;
            case 3:
                save_users_to_file("users.txt");
                printf("Exiting program.\n");
                exit(0);
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    }

    return 0;
}

