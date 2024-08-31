//gcc MD5.c -o MD5 -lssl -lcrypto -Wno-deprecated-declarations
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <termios.h>
#include <unistd.h>

#define MAX_USERS 10
#define USERNAME_LENGTH 20
#define PASSWORD_LENGTH (MD5_DIGEST_LENGTH * 2)
#define MFA_LENGTH (MD5_DIGEST_LENGTH * 2)
#define DOB_LENGTH  10
#define MAX_LOGIN_ATTEMPTS 3

char ans[DOB_LENGTH + 1];
const char *secu_question = "what is your date of birth?";

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

    unsigned char password_hash[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)password, strlen(password), password_hash);

    char hex_pass_hash[PASSWORD_LENGTH + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&hex_pass_hash[i * 2], "%02x", password_hash[i]);
    }

    unsigned char mfa_hash[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)mfa_code, strlen(mfa_code), mfa_hash);

    char hex_mfa_hash[MFA_LENGTH + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(&hex_mfa_hash[i * 2], "%02x", mfa_hash[i]);
    }

    printf("%s\n", secu_question);
    scanf("%s", ans);

    strcpy(users[num_users].username, username);
    strcpy(users[num_users].password, hex_pass_hash);
    strcpy(users[num_users].mfa_code, hex_mfa_hash);
    strcpy(users[num_users].secu_ans, ans);
    num_users++;

    save_users_to_file("users.txt");
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

                unsigned char input_pass_hash[MD5_DIGEST_LENGTH];
                MD5((unsigned char *)password, strlen(password), input_pass_hash);

                char input_hex_password_hash[PASSWORD_LENGTH + 1];
                for (int j = 0; j < MD5_DIGEST_LENGTH; j++) {
                    sprintf(&input_hex_password_hash[j * 2], "%02x", input_pass_hash[j]);
                }

                if (strcmp(users[i].password, input_hex_password_hash) == 0) {

                    char mfa_input[7];
                    printf("Enter your 6-digit MFA code: ");
                    disable_echo();
                    scanf("%s", mfa_input);
                    enable_echo();
                    printf("\n");

                    unsigned char input_mfa_hash[MD5_DIGEST_LENGTH];
                    MD5((unsigned char *)mfa_input, strlen(mfa_input), input_mfa_hash);

                    char input_hex_mfa_hash[MFA_LENGTH + 1];
                    for (int j = 0; j < MD5_DIGEST_LENGTH; j++) {
                        sprintf(&input_hex_mfa_hash[j * 2], "%02x", input_mfa_hash[j]);
                    }

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
                    disable_echo();
                    printf("Enter password: ");
                    scanf("%s", password);
                    enable_echo();
                    printf("\n");

                    printf("do you want to see the entered password(y/n):");
                    scanf("%s", &yn);
                    if (yn == 'y') {
                        printf("%s \n", password);
                    }

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

