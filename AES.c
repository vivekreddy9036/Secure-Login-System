#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <termios.h>
#include <unistd.h>

#define MAX_USERS 10
#define USERNAME_LENGTH 20
#define PASSWORD_LENGTH (SHA256_DIGEST_LENGTH * 2)
#define MFA_LENGTH (SHA256_DIGEST_LENGTH * 2)
#define DOB_LENGTH 10
#define MAX_LOGIN_ATTEMPTS 3

char ans[DOB_LENGTH + 1];
const char *secu_question = "what is your date of birth?";

typedef struct {
    char username[USERNAME_LENGTH];
    unsigned char password[PASSWORD_LENGTH + 1];
    unsigned char mfa_code[MFA_LENGTH + 1];
    char secu_ans[DOB_LENGTH + 1];
} User;

User users[MAX_USERS];
int num_users = 0;

AES_KEY aes_key;

void save_users_to_file(const char *filename);
void disable_echo();
void enable_echo();
void register_user(const char *username, const char *password, const char *mfa_code);
void load_users_from_file(const char *filename);
int login(const char *username, const char *password);

void encrypt_data(unsigned char *input, int input_len, unsigned char *output, unsigned char *key) {
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_encrypt(input, output, &aes_key);
}

void decrypt_data(unsigned char *input, int input_len, unsigned char *output, unsigned char *key) {
    AES_set_decrypt_key(key, 128, &aes_key);
    AES_decrypt(input, output, &aes_key);
}

void save_users_to_file(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    for (int i = 0; i < num_users; i++) {
        fwrite(&users[i], sizeof(User), 1, file);
    }

    fclose(file);
}

void load_users_from_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    while (fread(&users[num_users], sizeof(User), 1, file) == 1) {
        num_users++;
        if (num_users >= MAX_USERS) {
            break;
        }
    }

    fclose(file);
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

    unsigned char password_hash[PASSWORD_LENGTH];
    unsigned char mfa_hash[MFA_LENGTH];
    unsigned char encrypted_password[PASSWORD_LENGTH];
    unsigned char encrypted_mfa[MFA_LENGTH];

    EVP_MD_CTX *mdctx_pass = EVP_MD_CTX_new();
    EVP_MD_CTX *mdctx_mfa = EVP_MD_CTX_new();

    EVP_DigestInit(mdctx_pass, EVP_sha256());
    EVP_DigestUpdate(mdctx_pass, password, strlen(password));
    EVP_DigestFinal(mdctx_pass, password_hash, NULL);

    EVP_DigestInit(mdctx_mfa, EVP_sha256());
    EVP_DigestUpdate(mdctx_mfa, mfa_code, strlen(mfa_code));
    EVP_DigestFinal(mdctx_mfa, mfa_hash, NULL);

    encrypt_data(password_hash, PASSWORD_LENGTH, encrypted_password, password_hash);
    encrypt_data(mfa_hash, MFA_LENGTH, encrypted_mfa, mfa_hash);

    strcpy(users[num_users].username, username);
    memcpy(users[num_users].password, encrypted_password, PASSWORD_LENGTH);
    memcpy(users[num_users].mfa_code, encrypted_mfa, MFA_LENGTH);
    strcpy(users[num_users].secu_ans, secu_question);

    num_users++;

    save_users_to_file("users.dat");
}

int login(const char *username, const char *password) {
    int attempts_left = MAX_LOGIN_ATTEMPTS;
    while (attempts_left > 0) {
        for (int i = 0; i < num_users; i++) {
            if (strcmp(users[i].username, username) == 0) {
                unsigned char input_pass_hash[PASSWORD_LENGTH];
                unsigned char input_mfa_hash[MFA_LENGTH];

                decrypt_data(users[i].password, PASSWORD_LENGTH, input_pass_hash, users[i].password);
                decrypt_data(users[i].mfa_code, MFA_LENGTH, input_mfa_hash, users[i].mfa_code);

                if (memcmp(input_pass_hash, password, PASSWORD_LENGTH) == 0) {
                    char mfa_input[7];
                    printf("Enter your 6-digit MFA code: ");
                    scanf("%s", mfa_input);

                    if (memcmp(input_mfa_hash, mfa_input, MFA_LENGTH) == 0) {
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

int main() {
    int choice;
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH];
    char mfa_code[MFA_LENGTH];
    int attempts;
    char yn;

    load_users_from_file("users.dat");

    while (1) {
        printf("1. Login\n");
        printf("2. Register\n");
        printf("3. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice
);

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
                printf("Enter 6-digit multi-factor authentication code(MFA): ");
                disable_echo();
                scanf("%6s", mfa_code);
                enable_echo();
                printf("\n");
                getchar();
                printf("Do you want to see the entered password and MFA code (y/n): ");
                char yn;
                scanf(" %c", &yn);
                if (yn == 'y' || yn == 'Y') {
                    printf("Entered Password: %s\n", password);
                    printf("Entered MFA code: %s\n", mfa_code);
                }
                register_user(username, password, mfa_code);
                printf("User registered successfully.\n");
                break;
            case 3:
                save_users_to_file("users.dat");
                printf("Exiting program.\n");
                exit(0);
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    }

    return 0;
}

