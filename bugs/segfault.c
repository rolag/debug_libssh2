#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <libssh2.h>

static const char *username = "needspasswordchange";
static const char *password = "ChangeMe123";
static const char *scppath = "/home/needspasswordchange/file";
static const char *new_password = "NewPassword123";

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
    if (ret < 0) {
        printf("%s returned %i\n", msg, ret);
        exit(EXIT_FAILURE);
    }
    return ret;
}

void callback(LIBSSH2_SESSION *session, char **newpw, int *newpw_len, void **abstract)
{
    printf("Called callback\n");
    *newpw = (char *) new_password;
    *newpw_len = strlen(new_password);
}

int main(int argc, char** argv)
{
    handle(libssh2_init(0), "libssh2_init");

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons(12345);

    libssh2_socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    handle(connect(sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in)), "connect");

    LIBSSH2_SESSION *session = handle_ptr(libssh2_session_init(), "session_init");
    libssh2_session_set_blocking(session, 1);
    handle(libssh2_session_handshake(session, sock), "session_handshake");
    handle(libssh2_userauth_password_ex(session, username, strlen(username), password, strlen(password), callback), "password");
    if (!libssh2_userauth_authenticated(session)) {
        printf("not authenticated\n");
        exit(EXIT_FAILURE);
    }

    printf("calling scp_send64\n");

    LIBSSH2_CHANNEL *channel = handle_ptr(libssh2_scp_send64(session, scppath, 0700, 3, 0, 0), "scp_send64");
    printf("channel=%p\n", channel); // session->scpSend_state == 4 sent1
    // The following channel calls fail silently. No file is sent.
    handle(libssh2_channel_write(channel, "abc", 3), "write");
    handle(libssh2_channel_send_eof(channel), "send_eof");
    handle(libssh2_channel_wait_eof(channel), "wait_eof");
    handle(libssh2_channel_close(channel), "close");
    handle(libssh2_channel_wait_closed(channel), "wait_closed");
    handle(libssh2_channel_free(channel), "channel_free");

    printf("calling scp_send64 2\n"); // session->scpSend_state == 4 sent1

    LIBSSH2_CHANNEL *channel2 = handle_ptr(libssh2_scp_send64(session, scppath, 0700, 3, 0, 0), "scp_send64 2"); // segfault
    printf("channel2=%p\n", channel2);
    libssh2_channel_write(channel2, "xyz", 3);
    libssh2_channel_send_eof(channel2);
    libssh2_channel_wait_eof(channel2);
    libssh2_channel_close(channel2);
    libssh2_channel_wait_closed(channel2);
    libssh2_channel_free(channel2);

    exit(EXIT_SUCCESS);
}
