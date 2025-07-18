#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <sys/select.h>
#include <arpa/inet.h>

#define DEFAULT_PORT 9703
#define BUFFER_SIZE 8192
struct ProxyState {
    int client_fd;
    int replaced;
};
size_t write_cb(char *ptr, size_t size, size_t nmemb, void *statedata) {
    struct ProxyState state =  *(struct ProxyState *)statedata;
    int client_fd = state.client_fd;
    int replaced = state.replaced;
    size_t total = size * nmemb;
    if (!replaced && total >= 9 && memcmp(ptr, "HTTP/3 ", 7) == 0) {
        char *temp = malloc(total + 2);
        if(!temp) {
            goto send_original;
        }
        memcpy(temp, "HTTP/1.1 ", 9);
        memcpy(temp + 9, ptr + 7, total - 7);
        size_t sent = 0;
        while (sent < total + 2) {
            ssize_t r = send(client_fd, temp + sent, (total + 2) - sent, 0);
            if (r <= 0) {
                free(temp);
                return 0;
            }
            sent += r;
        }
        free(temp);
        state.replaced = 1;
        return total; 
    }

send_original:
    size_t sent = 0;
    while (sent < total) {
        ssize_t r = send(client_fd, ptr + sent, total - sent, 0);
        if (r <= 0) return 0;
        sent += r;
    }
    return total;
}


int handle_connect(const char *line, int client_fd) {
    char host[256];
    int port;
    if (sscanf(line, "CONNECT %255[^:]:%d", host, &port) != 2) return -1;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return -1;

    struct hostent *he = gethostbyname(host);
    if (!he) {
        close(server_fd);
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    if (connect(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect to target");
        close(server_fd);
        return -1;
    }
    const char *conn_established = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(client_fd, conn_established, strlen(conn_established), 0);
    char buf[4096];
    fd_set fds;
    int maxfd = client_fd > server_fd ? client_fd : server_fd;
    while (1) {
        FD_ZERO(&fds);
        FD_SET(client_fd, &fds);
        FD_SET(server_fd, &fds);
        int sel = select(maxfd + 1, &fds, NULL, NULL, NULL);
        if (sel < 0) break;
        if (FD_ISSET(client_fd, &fds)) {
            ssize_t r = recv(client_fd, buf, sizeof(buf), 0);
            if (r <= 0) break;
            send(server_fd, buf, r, 0);
        }
        if (FD_ISSET(server_fd, &fds)) {
            ssize_t r = recv(server_fd, buf, sizeof(buf), 0);
            if (r <= 0) break;
            send(client_fd, buf, r, 0);
        }
    }
    close(server_fd);
    return 0;
}
int recv_until_headers(int fd, char *buffer, size_t size) {
    size_t total = 0;
    while (total < size - 1) {
        ssize_t r = recv(fd, buffer + total, 1, 0);
        if (r <= 0) return -1;
        total += r;
        buffer[total] = 0;
        if (strstr(buffer, "\r\n\r\n")) break;
    }
    return (int)total;
}
CURLcode fetch(const char *url, int httpver, int client_fd) {
    CURL *curl = curl_easy_init();
    if (!curl) return CURLE_FAILED_INIT;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    struct ProxyState state = {
        .client_fd = client_fd,
        .replaced = 0
    };
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &state);

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    switch (httpver) {
        case 3:
            curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_3ONLY);
            break;
        case 1:
        default:
            curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
            break;
    }

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return res;
}

int main(int argc, char *argv[]) {
    curl_global_init(CURL_GLOBAL_ALL);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", argv[1]);
            return 1;
        }
    }
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen"); exit(1);
    }
    printf("Proxy listening on port %d\n", port);
    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        char buffer[BUFFER_SIZE] = {0};
        int len = recv_until_headers(client_fd, buffer, sizeof(buffer));
        if (len <= 0) {
            close(client_fd);
            continue;
        }
        char method[8], path[1024], version[16];
        if (sscanf(buffer, "%7s %1023s %15s", method, path, version) != 3) {
            dprintf(client_fd, "HTTP/1.1 400 Bad Request\r\n\r\n");
            close(client_fd);
            continue;
        }
        if (strcmp(method, "CONNECT") == 0) {
            if (handle_connect(buffer, client_fd) < 0) {
                dprintf(client_fd, "HTTP/1.1 502 Bad Gateway\r\n\r\n");
            }
            close(client_fd);
            continue;
        }else{
            if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0) {
                dprintf(client_fd, "HTTP/1.1 501 Not Implemented\r\n\r\n");
                close(client_fd);
                continue;
            }
        }
        char new_url[2048];
        if (strncmp(path, "http://", 7) == 0) {
            snprintf(new_url, sizeof(new_url), "https://%s", path + 7);
        } else {
            strncpy(new_url, path, sizeof(new_url));
            new_url[sizeof(new_url) - 1] = '\0';
        }
        printf("Fetching: %s (trying HTTP/3)\n", new_url);
        CURLcode res = fetch(new_url, 3, client_fd);
        if (res != CURLE_OK) {
            fprintf(stderr, "HTTP/3 failed: %s, trying HTTP/1.1\n", curl_easy_strerror(res));
            fetch(new_url, 1, client_fd);
        }

        close(client_fd);
    }
    curl_global_cleanup();
    return 0;
}
