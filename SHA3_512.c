#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <termios.h>
#include <unistd.h>

#define MAX_USERS 10
#define USERNAME_LENGTH 20
#define PASSWORD_LENGTH (crypto_hash_sha512_BYTES * 2)
#define MFA_LENGTH (crypto_hash_sha512_BYTES * 2)
#define DOB_LENGTH 10
#define MAX_LOGIN_ATTEMPTS 3

char ans[DOB_LENGTH + 1];
const char *secu_question = "What is your date of birth?";

typedef struct {
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH + 1];
    char mfa_code[MFA_LENGTH + 1];
    char secu_ans[DOB_LENGTH + 1];
} User;

User users[MAX_USERS];
int num_users = 0;

void save_users_to_file(const char *filename);

void disable_echo() {
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

void enable_echo() {
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

void register_user(const char *username, const char *password, const char *mfa_code) {
    if (num_users >= MAX_USERS) {
        printf("Maximum number of users reached.\n");
        return;
    }

    if (strlen(username) >= USERNAME_LENGTH || strlen(password) >= PASSWORD_LENGTH || strlen(mfa_code) != 6) {
        printf("Invalid input.\n");
        return;
    }

    unsigned char password_hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;

    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, (const unsigned char *)password, strlen(password));
    crypto_hash_sha512_final(&state, password_hash);

    char hex_pass_hash[PASSWORD_LENGTH + 1];
    sodium_bin2hex(hex_pass_hash, PASSWORD_LENGTH + 1, password_hash, crypto_hash_sha512_BYTES);

    unsigned char mfa_hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, (const unsigned char *)mfa_code, strlen(mfa_code));
    crypto_hash_sha512_final(&state, mfa_hash);

    char hex_mfa_hash[MFA_LENGTH + 1];
    sodium_bin2hex(hex_mfa_hash, MFA_LENGTH + 1, mfa_hash, crypto_hash_sha512_BYTES);

    printf("%s\n", secu_question);
    scanf("%s", ans);

    strcpy(users[num_users].username, username);
    strcpy(users[num_users].password, hex_pass_hash);
    strcpy(users[num_users].mfa_code, hex_mfa_hash);
    strcpy(users[num_users].secu_ans, ans);
    num_users++;

    save_users_to_file("users.txt");
}

int login(const char *username, const char *password) {
    int attempts_left = MAX_LOGIN_ATTEMPTS;
    while (attempts_left > 0) {
        for (int i = 0; i < num_users; i++) {
            if (strcmp(users[i].username, username) == 0) {
                unsigned char input_pass_hash[crypto_hash_sha512_BYTES];
                crypto_hash_sha512_state state;
                crypto_hash_sha512_init(&state);
                crypto_hash_sha512_update(&state, (const unsigned char *)password, strlen(password));
                crypto_hash_sha512_final(&state, input_pass_hash);

                char input_hex_password_hash[PASSWORD_LENGTH + 1];
                sodium_bin2hex(input_hex_password_hash, PASSWORD_LENGTH + 1, input_pass_hash, crypto_hash_sha512_BYTES);

                if (strcmp(users[i].password, input_hex_password_hash) == 0) {
                    char mfa_input[7];
                    printf("Enter your 6-digit MFA code: ");
                    disable_echo();
                    scanf("%s", mfa_input);
                    enable_echo();

                    unsigned char input_mfa_hash[crypto_hash_sha512_BYTES];
                    crypto_hash_sha512_init(&state);
                    crypto_hash_sha512_update(&state, (const unsigned char *)mfa_input, strlen(mfa_input));
                    crypto_hash_sha512_final(&state, input_mfa_hash);

                    char input_hex_mfa_hash[MFA_LENGTH + 1];
                    sodium_bin2hex(input_hex_mfa_hash, MFA_LENGTH + 1, input_mfa_hash, crypto_hash_sha512_BYTES);

                    if (strcmp(users[i].mfa_code, input_hex_mfa_hash) == 0) {
                        printf("Login successful!\n");
                        return 1;
                    } else {
                        printf("Incorrect MFA code. Please try again.\n");
                        attempts_left--;
                        printf("Attempts left: %d\n", attempts_left);
                    }
                } else {
                    printf("Incorrect password. Please try again.\n");
                    attempts_left--;
                    printf("Attempts left: %d\n", attempts_left);
                }
            }
        }
        printf("User not found.\n");
        return 0;
    }
    printf("Maximum login attempts reached. Please try again later.\n");
    return 0;
}

int main() {
    int choice;
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH];
    char mfa_code[MFA_LENGTH];
    int attempts;
    char yn;

    if (sodium_init() == -1) {
        printf("Error initializing libsodium\n");
        return 1;
    }

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
                    disable_echo();
                    scanf("%s", password);
                    enable_echo();
                    printf("\n");

                    if (login(username, password)) {
                        break;
                    }
 else {
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
                disable_echo();
                scanf("%s", password);
                enable_echo();
                printf("\n");
                printf("Enter 6-digit multi factor authentication code(MFA): ");
                disable_echo();
                scanf("%6s", mfa_code);
                enable_echo();
                printf("\n");
                getchar();
                printf("Do you want to see the entered password and MFA code (y/n): ");
                scanf(" %c", &yn);
                if (yn == 'y' || yn == 'Y') {
                    printf("Entered Password: %s\n", password);
                    printf("Entered MFA code: %s\n", mfa_code);
                }
                register_user(username, password, mfa_code);
                printf("User registered successfully.\n");
                break;
            case 3:
                printf("Exiting program.\n");
                exit(0);
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    }

    return 0;
}

void save_users_to_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    for (int i = 0; i < num_users; i++) {
        fprintf(file, "%s %s %s %s\n", users[i].username, users[i].password, users[i].mfa_code, users[i].secu_ans);
    }

    fclose(file);
}

