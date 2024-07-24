#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <libssh2.h>

#define CHANNELS 10
#define DATA_SIZE (16*1024*1024)

static const char *username = "passworduser";
static const char *password = "Password12345";

void init_data(char (*data)[DATA_SIZE], size_t index, char value)
{
    for (size_t i = 0; i < DATA_SIZE; i++) {
        data[index][i] = value;
    }
}

void *handle_ptr(void *ptr, char *msg)
{
    if (!ptr) {
        printf("%s returned NULL\n", msg);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

int handle(int ret, char *msg)
{
    if (ret < 0 && ret != LIBSSH2_ERROR_EAGAIN) {
        printf("%s returned %i\n", msg, ret);
        exit(EXIT_FAILURE);
    }
    return ret;
}

int main(int argc, char** argv)
{
    printf("initializing data\n");
    char (*write_data)[DATA_SIZE] = handle_ptr(malloc(sizeof(char[CHANNELS][DATA_SIZE])), "malloc write_data");

    init_data(write_data, 0, 'a');
    init_data(write_data, 1, 'b');
    init_data(write_data, 2, 'c');
    init_data(write_data, 3, 'd');
    init_data(write_data, 4, 'e');
    init_data(write_data, 5, 'f');
    init_data(write_data, 6, 'g');
    init_data(write_data, 7, 'h');
    init_data(write_data, 8, 'i');
    init_data(write_data, 9, 'j');

    printf("starting\n");
    handle(libssh2_init(0), "libssh2_init");

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons(12345);

    printf("connecting\n");
    libssh2_socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    handle(connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)), "connect");

    LIBSSH2_SESSION *session = handle_ptr(libssh2_session_init(), "session_init");
    libssh2_session_set_blocking(session, 1);
    handle(libssh2_session_handshake(session, sock), "session_handshake");
    handle(libssh2_userauth_password_ex(session, username, strlen(username), password, strlen(password), NULL), "password");
    if (!libssh2_userauth_authenticated(session)) {
        printf("not authenticated\n");
        exit(EXIT_FAILURE);
    }
    printf("connected\n");

    LIBSSH2_CHANNEL *channels[CHANNELS] = {};

    for (size_t i = 0; i < CHANNELS; i++) {
        printf("starting channel %lu\n", i);
        channels[i] = handle_ptr(libssh2_channel_open_ex(
            session,
            "session",
            7,
            LIBSSH2_CHANNEL_WINDOW_DEFAULT,
            LIBSSH2_CHANNEL_PACKET_DEFAULT,
            NULL,
            0
        ), "channel_open_ex");
        handle(libssh2_channel_exec(channels[i], "cat"), "exec");
    }

    libssh2_session_set_blocking(session, 0);
    size_t written_data[CHANNELS] = {};
    bool sent_eof[CHANNELS] = {};
    char (*read_data)[DATA_SIZE*2] = handle_ptr(malloc(sizeof(char[CHANNELS][DATA_SIZE*2])), "malloc read_data");
    size_t read_data_len[CHANNELS] = {};
    bool recv_eof[CHANNELS] = {};
    size_t eof_size = 0;
    struct timeval times[CHANNELS*2] = {};
    struct timeval now = {};
    struct timeval result = {};
    printf("starting read/write\n");
    while (eof_size < CHANNELS * 2) {
        // write
        for (size_t i = 0; i < CHANNELS; i++) {
            while (true) {
                if (sent_eof[i]) {
                    break;
                }
                gettimeofday(&now, NULL);
                timersub(&times[i], &now, &result);
                if (result.tv_usec/1000 < 100) {
                    break;
                }
                printf("Channel %lu ", i);
                if (written_data[i] >= DATA_SIZE) {
                    printf("sending eof\n");
                    if (handle(libssh2_channel_send_eof(channels[i]), "send_eof") == LIBSSH2_ERROR_EAGAIN) {
                        times[i] = now;
                        break;
                    }
                    printf("sent eof\n");
                    sent_eof[i] = true;
                    eof_size += 1;
                    break;
                }
                ssize_t written = handle(libssh2_channel_write_ex(channels[i], 0, &write_data[i][written_data[i]], DATA_SIZE - written_data[i]), "write");
                if (written == LIBSSH2_ERROR_EAGAIN) {
                    printf("write(%lu)=%li\n", DATA_SIZE - written_data[i], written);
                    times[i] = now;
                    break;
                }
                written_data[i] += written;
                printf("write(%lu)=%li -> %lu\n", DATA_SIZE - written_data[i], written, written_data[i]);
            }
        }
        // read
        for (size_t i = 0; i < CHANNELS; i++) {
            while (true) {
                if (recv_eof[i]) {
                    break;
                }
                gettimeofday(&now, NULL);
                timersub(&times[i], &now, &result);
                if (result.tv_usec/1000 < 100) {
                    break;
                }
                printf("Channel %lu ", i);
                ssize_t read = handle(libssh2_channel_read(channels[i], &read_data[i][read_data_len[i]], 1024*1024), "read");
                if (read == LIBSSH2_ERROR_EAGAIN) {
                    times[10+i] = now;
                    printf("read=%li -> %lu\n", read, read_data_len[i]+read);
                    break;
                }
                printf("read=%li+%li -> %lu\n", read, read_data_len[i], read_data_len[i]+read);
                if (read == 0) {
                    recv_eof[i] = true;
                    eof_size += 1;
                } else {
                    read_data_len[i] += read;
                }
            }
        }
    }

    libssh2_session_set_blocking(session, 1);

    printf("----------------\n");

    printf("cleaning up\n");
    bool return_error = false;
    for (size_t i = 0; i < CHANNELS; i++) {
        printf("Channel %lu total_sent=%lu total_read=%lu\n", i, written_data[i], read_data_len[i]);
        if (written_data[i] != read_data_len[i] || read_data_len[i] != DATA_SIZE) {
            return_error = true;
        }
    }

    for (size_t i = 0; i < CHANNELS; i++) {
        handle(libssh2_channel_wait_eof(channels[i]), "wait_eof");
        handle(libssh2_channel_close(channels[i]), "close");
        handle(libssh2_channel_wait_closed(channels[i]), "wait_closed");
        handle(libssh2_channel_free(channels[i]), "channel_free");
    }
    handle(libssh2_session_free(session), "session_free");
    free(write_data);
    free(read_data);

    if (return_error) {
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
