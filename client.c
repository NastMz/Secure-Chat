#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>


#define BUFFER_SIZE 4096
#define NAME_LEN 32

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

char name[NAME_LEN];

int welcome_received = 0;
int error_received = 0;
char *host;
int port = 8080;

// Global variable to store the key pair
RSA *keypair;

/**
 *
 * Generate a pair of RSA keys and store them in the global variables.
 * Send the public key as a buffer over a socket, preceded by the size of the key.
 *
 * @param sockfd The socket file descriptor
 * @return 0 on success, -1 on failure
 */
int generate_and_send_keypair(int sockfd) {
    // Generate the key pair
    keypair = RSA_generate_key(2048, 65537, NULL, NULL);
    if (keypair == NULL) {
        printf("Error generating RSA key pair.\n");
        return -1;
    }

    // Get the size of the public key
    int key_size = i2d_RSAPublicKey(keypair, NULL);
    if (key_size < 0) {
        printf("Error getting size of RSA public key.\n");
        return -1;
    }

    // Allocate memory for the public key
    unsigned char *key_buffer = (unsigned char *) malloc(key_size);
    if (key_buffer == NULL) {
        printf("Error allocating memory for RSA public key.\n");
        return -1;
    }

    // Convert the public key to a DER-encoded buffer
    unsigned char *temp = key_buffer;
    i2d_RSAPublicKey(keypair, &temp);

    // Send the size of the public key to the server
    if (send(sockfd, &key_size, sizeof(key_size), 0) < 0) {
        printf("Error sending size of RSA public key.\n");
        free(key_buffer);
        return -1;
    }

    // Send the public key to the server
    if (send(sockfd, key_buffer, key_size, 0) < 0) {
        printf("Error sending RSA public key.\n");
        free(key_buffer);
        return -1;
    }

    // Free the memory allocated for the public key
    free(key_buffer);
    return 0;
}

/**
 *
 * Function to encrypt a message using the public key.
 *
 * @param plaintext The message to encrypt.
 * @param key The public key to use.
 * @param ciphertext The buffer to store the encrypted message.
 *
 * @return The size of the encrypted message.
 */
int encrypt_message(const unsigned char *plaintext, RSA *key, unsigned char *ciphertext) {
    // Encrypt the plaintext using RSA
    int size = RSA_public_encrypt(strlen(plaintext), plaintext, ciphertext, key, RSA_PKCS1_OAEP_PADDING);
    if (size < 0){
        perror("Error encrypting the message");
        exit(EXIT_FAILURE);
    }

    return size;
}

/**
 *
 * Function to decrypt the message using RSA.
 *
 * @param ciphertext_length The length of the ciphertext.
 * @param ciphertext The ciphertext to be decrypted.
 * @param plaintext The buffer to store the message after decryption.
 */
void decrypt_message(int ciphertext_length, const unsigned char *ciphertext, unsigned char *plaintext) {

    // Decrypt the ciphertext using private key
    int size = RSA_private_decrypt(ciphertext_length, ciphertext, plaintext, keypair, RSA_PKCS1_OAEP_PADDING);
    if (size < 0){
        perror("Error decrypting the message");
        exit(EXIT_FAILURE);
    }
}

/**
 *
 * Function to encode a buffer to base64.
 *
 * @param ciphertext The buffer to encode.
 * @param ciphertext_size The size of the buffer to encode.
 * @param serialized_message The buffer to store the encoded message.
 *
 * @return The size of the encoded message.
 */
int serialize_message(unsigned char *ciphertext, int ciphertext_size, char *serialized_message) {
    // Create a memory BIO
    BIO *bio = BIO_new(BIO_s_mem());

    // Set the BIO to base64 filter mode
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_push(b64, bio);

    // Write the ciphertext to the BIO
    BIO_write(b64, ciphertext, ciphertext_size);

    // Flush the BIO
    BIO_flush(b64);

    // Get the serialized message from the BIO
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    memcpy(serialized_message, bptr->data, bptr->length);
    serialized_message[bptr->length] = '\0';

    // Free the BIOs
    BIO_free_all(b64);

    return strlen(serialized_message);
}

/**
 * Deserialize a base64 serialized message.
 *
 * @param serialized_message  The serialized message.
 * @param serialized_message_len The length of the serialized message.
 * @param deserialized_message The buffer to store the deserialized message.
 * @param deserialized_message_len The length of the deserialized message.
 */
void deserialize_message(char *serialized_message, int serialized_message_len, unsigned char *deserialized_message, int deserialized_message_len)
{
    BIO *b64;
    BIO *bmem;
    int ret;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(serialized_message, serialized_message_len);
    bmem = BIO_push(b64, bmem);
    ret = BIO_read(bmem, deserialized_message, serialized_message_len);

    BIO_free_all(bmem);

    if (ret < 0 || ret < deserialized_message_len) {
        printf("Error decoding base64 data\n");
        exit(EXIT_FAILURE);
    }
}


/**
 *
 * Function to receive another client's public key
 *
 * @param priv_sockfd The socket descriptor for the connection.
 * @return The public key of the other client.
 */
RSA *receive_client_key(int priv_sockfd) {
    // Receive the size of the public key
    int key_size;
    if (recv(priv_sockfd, &key_size, sizeof(key_size), 0) < 0) {
        printf("Error receiving size of RSA public key.\n");
        return NULL;
    }

    // Allocate memory for the public key
    unsigned char *key_buffer = (unsigned char *) malloc(key_size);
    if (key_buffer == NULL) {
        printf("Error allocating memory for RSA public key.\n");
        return NULL;
    }

    // Receive the public key
    if (recv(priv_sockfd, key_buffer, key_size, 0) < 0) {
        printf("Error receiving RSA public key.\n");
        free(key_buffer);
        return NULL;
    }

    // Convert the DER-encoded buffer to an RSA public key
    const unsigned char *temp = key_buffer;
    RSA *public_key = d2i_RSAPublicKey(NULL, &temp, key_size);
    if (public_key == NULL) {
        printf("Error converting RSA public key from DER-encoded buffer.\n");
        exit(EXIT_FAILURE);
    }

    // Free the memory allocated for the public key
    free(key_buffer);

    return public_key;
}


/**
 *
 * Connects to the server at the specified host and port.
 *
 * @param host The hostname or IP address of the server.
 * @param port The port number of the server.
 *
 * @return The socket descriptor for the connection.
*/
int connect_to_server(char *host, int port) {
    int sockfd;
    struct sockaddr_in serv_addr;

// Create a socket
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

// Set the server address
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = PF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr(host);

// Connect to the server
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}


/**
 *
 * Receives a message from the server.
 *
 * @param sockfd The socket descriptor for the connection.
 * @param buffer The buffer to store the message.
 */
void receive_message(int sockfd, char *buffer) {
    int bytes_received = recv(sockfd, buffer, BUFFER_SIZE, 0);
    if (bytes_received < 0) {
        perror("recv");
        exit(EXIT_FAILURE);
    } else if (bytes_received == 0) {
        // The server closed the connection
        printf("Server closed connection. Closing program...\n");
        exit(EXIT_SUCCESS);
    }
}

void send_private_message(int sockfd, int priv_sockfd, char *buffer) {
    // Parse the recipient's name and the message from the buffer
    char *recipient = strtok(buffer + strlen("/private"), " ");
    char *plaintext = strtok(NULL, "\n");

    if (recipient == NULL || plaintext == NULL) {
        fprintf(stderr, "Error: Invalid private message format\n");
        return;
    }

    char message[BUFFER_SIZE];

    // Get the recipient's public key
    sprintf(message, "/key %s", recipient);
    send(sockfd, message, strlen(message), 0);

    RSA *public_key = receive_client_key(priv_sockfd);

    // Encrypt the message
    unsigned char *ciphertext = malloc(BUFFER_SIZE);
    int ciphertext_size = encrypt_message(plaintext, public_key, ciphertext);

    // Serialize the message
    unsigned char *b64encoded_message = malloc(BUFFER_SIZE);
    int b64encoded_message_size = serialize_message(ciphertext, ciphertext_size, (char *) b64encoded_message);

    // Send the serialized message to the server
    sprintf(message, "%s %s %d %d ", "/private", recipient, ciphertext_size, b64encoded_message_size);
    memcpy(message + strlen(message), b64encoded_message, b64encoded_message_size);
    send(sockfd, message, strlen(message), 0);

    free(ciphertext);
    free(b64encoded_message);
}

/**
 *
 * Sends a message to the server.
 *
 * @param sockfd The socket descriptor for the connection.
 * @param priv_sockfd The socket descriptor for the exclusive server-client communication.
 * @param buffer The message to send.
 */
void send_message(int sockfd, int priv_sockfd, char *buffer) {
    // Check if the message is a private message
    char const *private_prefix = "/private";
    if (strncmp(buffer, private_prefix, strlen(private_prefix)) == 0) {
        send_private_message(sockfd, priv_sockfd, buffer);
    } else {
        // Send the message as normal if it is not a private message
        send(sockfd, buffer, strlen(buffer), 0);
    }
}


/**
 *
 * Receives messages from the server in a separate thread.
 *
 * @param arg The socket descriptor for the connection.
 *
 * @return Always NULL.
 */
void *receive_messages(void *arg) {
    int sockfd = *((int *) arg);

    char buffer[BUFFER_SIZE];
    while (1) {

        receive_message(sockfd, buffer);

        // Check if the message is a private message
        char *private_prefix = "[private]";
        if (strncmp(buffer, private_prefix, strlen(private_prefix)) == 0) {

            // Parse the sender's name from the message
            char *saveptr;

            // Split the buffer into the receiver's name, the message sizes and the message
            char *sender = strtok_r(buffer + strlen(private_prefix), " ", &saveptr);
            char *message_size = strtok_r(NULL, " ", &saveptr);
            char *b64string_size = strtok_r(NULL, " ", &saveptr);
            char *b64string = strtok_r(NULL, "", &saveptr);

            // Deserialize the message
            unsigned char *decoded_message = malloc(atoi(message_size));
            deserialize_message(b64string, atoi(b64string_size), decoded_message, atoi(message_size));

            // Decrypt the message
            unsigned char *plaintext = malloc(BUFFER_SIZE);
            decrypt_message(atoi(message_size), decoded_message, plaintext);

            // Save the decrypted message
            sprintf(buffer, "%s %s %s", private_prefix, sender, plaintext);

            free(decoded_message);
            free(plaintext);
        }

        if (strstr(buffer, "[system] Error") != NULL) {
            error_received = 1;
            pthread_cond_signal(&cond);
        }

        if (strstr(buffer, "access_successfully") != NULL) {
            pthread_mutex_lock(&mutex);
            welcome_received = 1;
            error_received = 0;
            pthread_cond_signal(&cond);
            pthread_mutex_unlock(&mutex);
        } else {
            // Print the line
            printf("%s\n", buffer);
            fflush(stdout);
        }

        memset(buffer, 0, BUFFER_SIZE);

    }

    return NULL;
}

/**
 * Handle the broken pipe signal.
 *
 * @param signal The signal number.
 */
void sigpipe_handler(int signal) {
    printf("Server closed connection. Closing program...\n");
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s host port\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    host = argv[1];
    port = atoi(argv[2]);
    // Connect to the server
    int sockfd = connect_to_server(host, port);

    // SIGPIPE signal handler
    signal(SIGPIPE, sigpipe_handler);

    // Start the separate thread to receive messages from the server
    pthread_t thread;
    pthread_create(&thread, NULL, receive_messages, &sockfd);

    int priv_sockfd = connect_to_server(host, port + 1);

    char buffer[BUFFER_SIZE];
    char aux_name[NAME_LEN];

    memset(buffer, 0, BUFFER_SIZE);

    // Generate RSA key pair
    if (generate_and_send_keypair(sockfd) < 0) {
        perror("Generate and send key pair failed");
        exit(EXIT_FAILURE);
    }

    // Wait until we receive the welcome message from the server
    pthread_mutex_lock(&mutex);
    while (!welcome_received && !error_received) {
        fgets(aux_name, NAME_LEN, stdin);
        send_message(sockfd, priv_sockfd, aux_name);
        strcpy(name, aux_name);
        memset(aux_name, 0, NAME_LEN);
        pthread_cond_wait(&cond, &mutex);
        if (error_received) {
            error_received = 0;
        }
    }
    pthread_mutex_unlock(&mutex);

    // Read and send messages from the user
    while (1) {

        // Read the message from the user
        fgets(buffer, BUFFER_SIZE, stdin);

        // Send the message to the server
        send_message(sockfd, priv_sockfd, buffer);
        if (strcmp(buffer, "/exit") == 0) {
            break;
        }
    }

    close(sockfd);
    pthread_exit(NULL);
    return 0;
}