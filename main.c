#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <uv.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#define DEFAULT_PORT 9703
#define BUFFER_SIZE 8192
#define HOST_BUFFER_SIZE 100

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct {
    uv_tcp_t handle;
    char buffer[BUFFER_SIZE];
    int replaced;
    int version;
    char *headers;
    char url[2048];
} client_t;

typedef struct {
    uv_tcp_t *client;
    uv_tcp_t *server;
    int active;
} tunnel_t;

struct ProxyState {
    uv_stream_t *client;
    int replaced;
    int version;
};

struct HostEntry {
    char hostname[256];
    int http3_failed;
};

struct HostBuffer {
    struct HostEntry entries[HOST_BUFFER_SIZE];
    int index;
    int count;
};

static struct HostBuffer host_buffer = {0};

char* extract_hostname(const char* url, char* hostname, size_t size) {
    const char* start;
    if (strncmp(url, "https://", 8) == 0) {
        start = url + 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        start = url + 7;
    } else {
        start = url;
    }
    
    const char* end = strchr(start, '/');
    if (!end) end = strchr(start, ':');
    if (!end) end = start + strlen(start);
    
    size_t len = end - start;
    if (len >= size) len = size - 1;
    
    memcpy(hostname, start, len);
    hostname[len] = '\0';
    return hostname;
}
int check_host_http3_failed(const char* hostname) {
    const int MIN_COUNT = 2;
    int count = 0;
    for (int i = 0; i < host_buffer.count; i++) {
        if (strcmp(host_buffer.entries[i].hostname, hostname) == 0) {
            if (host_buffer.entries[i].http3_failed) {
                count++;
                if (count >= MIN_COUNT) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

void add_host_entry(const char* hostname, int http3_failed) {
    for (int i = 0; i < host_buffer.count; i++) {
        if (strcmp(host_buffer.entries[i].hostname, hostname) == 0) {
            host_buffer.entries[i].http3_failed = http3_failed;
            return;
        }
    }
    size_t hostname_len = strlen(hostname);
    size_t max_len = sizeof(host_buffer.entries[host_buffer.index].hostname) - 1;
    if (hostname_len > max_len) hostname_len = max_len;
    memcpy(host_buffer.entries[host_buffer.index].hostname, hostname, hostname_len);
    host_buffer.entries[host_buffer.index].hostname[hostname_len] = '\0';
    host_buffer.entries[host_buffer.index].http3_failed = http3_failed;
    
    host_buffer.index = (host_buffer.index + 1) % HOST_BUFFER_SIZE;
    if (host_buffer.count < HOST_BUFFER_SIZE) {
        host_buffer.count++;
    }
}
void on_write(uv_write_t *req, int status) {
    write_req_t *wr = (write_req_t *)req;
    if (wr->buf.base) {
        free(wr->buf.base);
    }
    free(wr);
}

size_t write_cb(char *ptr, size_t size, size_t nmemb, void *statedata) {
    struct ProxyState *state = (struct ProxyState *)statedata;
    uv_stream_t *client = state->client;
    int replaced = state->replaced;
    int version = state->version;
    size_t total = size * nmemb;
    
    char *data_to_send = NULL;
    size_t send_size = total;
    
    if (!replaced && total >= 9 && memcmp(ptr, "HTTP/3 ", 7) == 0) {
        data_to_send = malloc(total + 2);
        if (!data_to_send) {
            return 0;
        }
        memcpy(data_to_send, "HTTP/1.1 ", 9);
        memcpy(data_to_send + 9, ptr + 7, total - 7);
        send_size = total + 2;
        state->replaced = 1;
    } else if (!replaced && total >= 9 && memcmp(ptr, "HTTP/2 ", 7) == 0) {
        data_to_send = malloc(total + 2);
        if (!data_to_send) {
            return 0;
        }
        memcpy(data_to_send, "HTTP/1.1 ", 9);
        memcpy(data_to_send + 9, ptr + 7, total - 7);
        send_size = total + 2;
        state->replaced = 1;
    } else {
        data_to_send = malloc(total);
        if (!data_to_send) {
            return 0;
        }
        memcpy(data_to_send, ptr, total);
    }
    
    write_req_t *req = (write_req_t *)malloc(sizeof(write_req_t));
    if (!req) {
        free(data_to_send);
        return 0;
    }
    
    req->buf = uv_buf_init(data_to_send, send_size);
    int r = uv_write((uv_write_t *)req, client, &req->buf, 1, on_write);
    if (r) {
        free(data_to_send);
        free(req);
        return 0;
    }
    
    return total;
}


void tunnel_read_client(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
void tunnel_read_server(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
}

void tunnel_close_cb(uv_handle_t *handle) {
    free(handle);
}

void tunnel_write_cb(uv_write_t *req, int status) {
    free(req);
}

void tunnel_read_client(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    tunnel_t *tunnel = (tunnel_t *)stream->data;
    
    if (nread < 0) {
        if (buf->base) free(buf->base);
        if (tunnel->active) {
            tunnel->active = 0;
            uv_close((uv_handle_t *)tunnel->client, tunnel_close_cb);
            uv_close((uv_handle_t *)tunnel->server, tunnel_close_cb);
            free(tunnel);
        }
        return;
    }
    
    if (nread == 0) {
        if (buf->base) free(buf->base);
        return;
    }
    
    uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
    uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
    uv_write(req, (uv_stream_t *)tunnel->server, &wrbuf, 1, tunnel_write_cb);
}

void tunnel_read_server(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    tunnel_t *tunnel = (tunnel_t *)stream->data;
    
    if (nread < 0) {
        if (buf->base) free(buf->base);
        if (tunnel->active) {
            tunnel->active = 0;
            uv_close((uv_handle_t *)tunnel->client, tunnel_close_cb);
            uv_close((uv_handle_t *)tunnel->server, tunnel_close_cb);
            free(tunnel);
        }
        return;
    }
    
    if (nread == 0) {
        if (buf->base) free(buf->base);
        return;
    }
    
    uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
    uv_buf_t wrbuf = uv_buf_init(buf->base, nread);
    uv_write(req, (uv_stream_t *)tunnel->client, &wrbuf, 1, tunnel_write_cb);
}

void on_connect_complete(uv_connect_t *req, int status) {
    tunnel_t *tunnel = (tunnel_t *)req->data;
    free(req);
    
    if (status < 0) {
        const char *response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        write_req_t *wr = (write_req_t *)malloc(sizeof(write_req_t));
        wr->buf = uv_buf_init(strdup(response), strlen(response));
        uv_write((uv_write_t *)wr, (uv_stream_t *)tunnel->client, &wr->buf, 1, on_write);
        
        uv_close((uv_handle_t *)tunnel->client, tunnel_close_cb);
        uv_close((uv_handle_t *)tunnel->server, tunnel_close_cb);
        free(tunnel);
        return;
    }
    
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    write_req_t *wr = (write_req_t *)malloc(sizeof(write_req_t));
    wr->buf = uv_buf_init(strdup(response), strlen(response));
    uv_write((uv_write_t *)wr, (uv_stream_t *)tunnel->client, &wr->buf, 1, on_write);
    
    tunnel->active = 1;
    tunnel->client->data = tunnel;
    tunnel->server->data = tunnel;
    
    uv_read_start((uv_stream_t *)tunnel->client, alloc_buffer, tunnel_read_client);
    uv_read_start((uv_stream_t *)tunnel->server, alloc_buffer, tunnel_read_server);
}

void on_resolved(uv_getaddrinfo_t *resolver, int status, struct addrinfo *res) {
    tunnel_t *tunnel = (tunnel_t *)resolver->data;
    
    if (status < 0 || !res) {
        const char *response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        write_req_t *wr = (write_req_t *)malloc(sizeof(write_req_t));
        wr->buf = uv_buf_init(strdup(response), strlen(response));
        uv_write((uv_write_t *)wr, (uv_stream_t *)tunnel->client, &wr->buf, 1, on_write);
        
        uv_close((uv_handle_t *)tunnel->client, tunnel_close_cb);
        free(tunnel->server);
        free(tunnel);
        uv_freeaddrinfo(res);
        free(resolver);
        return;
    }
    
    uv_connect_t *connect_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
    connect_req->data = tunnel;
    uv_tcp_connect(connect_req, tunnel->server, res->ai_addr, on_connect_complete);
    
    uv_freeaddrinfo(res);
    free(resolver);
}

int handle_connect(const char *line, uv_tcp_t *client, uv_loop_t *loop) {
    char host[256];
    int port;
    if (sscanf(line, "CONNECT %255[^:]:%d", host, &port) != 2) {
        return -1;
    }
    
    tunnel_t *tunnel = (tunnel_t *)malloc(sizeof(tunnel_t));
    tunnel->client = client;
    tunnel->server = (uv_tcp_t *)malloc(sizeof(uv_tcp_t));
    tunnel->active = 0;
    uv_tcp_init(loop, tunnel->server);
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    uv_getaddrinfo_t *resolver = (uv_getaddrinfo_t *)malloc(sizeof(uv_getaddrinfo_t));
    resolver->data = tunnel;
    
    int r = uv_getaddrinfo(loop, resolver, on_resolved, host, port_str, &hints);
    if (r) {
        free(resolver);
        free(tunnel->server);
        free(tunnel);
        return -1;
    }
    
    return 0;
}
CURLcode fetch(const char *url, int httpver, uv_stream_t *client, const char *headers) {
    CURL *curl = curl_easy_init();
    if (!curl) return CURLE_FAILED_INIT;
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    struct ProxyState state = {
        .client = client,
        .replaced = 0,
        .version = httpver
    };
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &state);

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);  // 5 second connection timeout
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);        // 30 second total timeout
    
#ifdef PRERESOLVE_DNS
    // Pre-resolve DNS for HTTP/3 to work around ngtcp2 DNS hang on Windows
    struct curl_slist *resolve_list = NULL;
    if (httpver == 3) {
        char hostname[256];
        extract_hostname(url, hostname, sizeof(hostname));
        
        // Determine port (443 for https, 80 for http)
        int port = 443;
        if (strncmp(url, "http://", 7) == 0) port = 80;
        
        // Use getaddrinfo to resolve synchronously
        struct addrinfo hints = {0}, *res = NULL;
        hints.ai_family = AF_INET;  // IPv4
        hints.ai_socktype = SOCK_STREAM;
        
        if (getaddrinfo(hostname, NULL, &hints, &res) == 0 && res) {
            struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
            
            char resolve_entry[512];
            snprintf(resolve_entry, sizeof(resolve_entry), "%s:%d:%s", hostname, port, ip);
            resolve_list = curl_slist_append(resolve_list, resolve_entry);
            curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve_list);
            
            freeaddrinfo(res);
        }
    }
#endif
    struct curl_slist *header_list = NULL;
    if (headers && strlen(headers) > 0) {
        char *headers_copy = strdup(headers);
        char *line = strtok(headers_copy, "\r\n");
        while (line != NULL) {
            if (strlen(line) > 0 && strchr(line, ':') != NULL) {
                if (strncasecmp(line, "Host:", 5) != 0 &&
                    strncasecmp(line, "Content-Length:", 15) != 0 &&
                    strncasecmp(line, "Connection:", 11) != 0 &&
                    strncasecmp(line, "Proxy-", 6) != 0) {
                    header_list = curl_slist_append(header_list, line);
                }
            }
            line = strtok(NULL, "\r\n");
        }
        free(headers_copy);
    }
    
    if (header_list) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

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
    
    if (header_list) {
        curl_slist_free_all(header_list);
    }
#ifdef PRERESOLVE_DNS
    if (resolve_list) {
        curl_slist_free_all(resolve_list);
    }
#endif
    curl_easy_cleanup(curl);
    return res;
}

void on_client_close(uv_handle_t *handle) {
    client_t *client = (client_t *)handle;
    if (client->headers) {
        free(client->headers);
    }
    free(client);
}

void process_request(client_t *client, uv_loop_t *loop) {
    char method[8], path[1024], version[16];
    if (sscanf(client->buffer, "%7s %1023s %15s", method, path, version) != 3) {
        const char *response = "HTTP/1.1 400 Bad Request\r\n\r\n";
        write_req_t *req = (write_req_t *)malloc(sizeof(write_req_t));
        req->buf = uv_buf_init(strdup(response), strlen(response));
        uv_write((uv_write_t *)req, (uv_stream_t *)&client->handle, &req->buf, 1, on_write);
        uv_close((uv_handle_t *)&client->handle, on_client_close);
        return;
    }
    
    char *headers_start = strstr(client->buffer, "\r\n");
    if (headers_start) {
        client->headers = strdup(headers_start + 2);
    }
    
    if (strcmp(method, "CONNECT") == 0) {
        if (handle_connect(client->buffer, &client->handle, loop) < 0) {
            const char *response = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
            write_req_t *req = (write_req_t *)malloc(sizeof(write_req_t));
            req->buf = uv_buf_init(strdup(response), strlen(response));
            uv_write((uv_write_t *)req, (uv_stream_t *)&client->handle, &req->buf, 1, on_write);
            uv_close((uv_handle_t *)&client->handle, on_client_close);
        }
        return;
    }
    
    if (strncmp(path, "http://", 7) == 0) {
        snprintf(client->url, sizeof(client->url), "https://%s", path + 7);
    } else {
        size_t path_len = strlen(path);
        if (path_len >= sizeof(client->url)) path_len = sizeof(client->url) - 1;
        memcpy(client->url, path, path_len);
        client->url[path_len] = '\0';
    }
    
    char hostname[256];
    extract_hostname(client->url, hostname, sizeof(hostname));
    
    int skip_http3 = check_host_http3_failed(hostname);
    
    if (skip_http3) {
        printf("Fetching: %s (skipping HTTP/3 due to previous failure)\n", client->url);
        fflush(stdout);
        fetch(client->url, 1, (uv_stream_t *)&client->handle, client->headers);
        add_host_entry(hostname, 1);
    } else {
        printf("Fetching: %s (trying HTTP/3)\n", client->url);
        fflush(stdout);
        CURLcode res = fetch(client->url, 3, (uv_stream_t *)&client->handle, client->headers);
        if (res != CURLE_OK) {
            const char *err = curl_easy_strerror(res);
            //TODO: this relies on timeouts and errors, implement a way to early detect HTTP/3 support
            if (strncmp(err, "Could not resolve hostname", 26) == 0 || 
                strncmp(err, "Could not connect to server", 27) == 0) {
                printf("Could not resolve or connect to server, aborting.\n");
                add_host_entry(hostname, 1);
            } else {
                fprintf(stderr, "HTTP/3 failed: %s, trying HTTP/1.1\n", err);
                add_host_entry(hostname, 1);
                fetch(client->url, 1, (uv_stream_t *)&client->handle, client->headers);
            }
        } else {
            add_host_entry(hostname, 0);
        }
    }
    
    uv_close((uv_handle_t *)&client->handle, on_client_close);
}

void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    client_t *client = (client_t *)stream;
    
    if (nread < 0) {
        if (buf->base) free(buf->base);
        uv_close((uv_handle_t *)stream, on_client_close);
        return;
    }
    
    if (nread == 0) {
        if (buf->base) free(buf->base);
        return;
    }
    
    size_t current_len = strlen(client->buffer);
    size_t to_copy = nread;
    if (current_len + to_copy >= BUFFER_SIZE) {
        to_copy = BUFFER_SIZE - current_len - 1;
    }
    
    memcpy(client->buffer + current_len, buf->base, to_copy);
    client->buffer[current_len + to_copy] = '\0';
    free(buf->base);
    
    if (strstr(client->buffer, "\r\n\r\n")) {
        uv_read_stop(stream);
        process_request(client, stream->loop);
    }
}

void on_connection(uv_stream_t *server, int status) {
    if (status < 0) {
        fprintf(stderr, "Connection error: %s\n", uv_strerror(status));
        return;
    }
    
    client_t *client = (client_t *)malloc(sizeof(client_t));
    memset(client, 0, sizeof(client_t));
    
    uv_tcp_init(server->loop, &client->handle);
    
    if (uv_accept(server, (uv_stream_t *)&client->handle) == 0) {
        uv_read_start((uv_stream_t *)&client->handle, alloc_buffer, on_read);
    } else {
        uv_close((uv_handle_t *)&client->handle, on_client_close);
    }
}

int main(int argc, char *argv[]) {
    curl_global_init(CURL_GLOBAL_ALL);
    
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number: %s\n", argv[1]);
            return 1;
        }
    }
    
    uv_loop_t *loop = uv_default_loop();
    uv_tcp_t server;
    uv_tcp_init(loop, &server);
    
    struct sockaddr_in6 addr;
    uv_ip6_addr("::", port, &addr);
    
    uv_tcp_bind(&server, (const struct sockaddr *)&addr, 0);
    
    int r = uv_listen((uv_stream_t *)&server, 128, on_connection);
    if (r) {
        fprintf(stderr, "Listen error: %s\n", uv_strerror(r));
        return 1;
    }
    
    printf("Proxy listening on port %d\n", port);
    fflush(stdout);
    
    uv_run(loop, UV_RUN_DEFAULT);
    
    curl_global_cleanup();
    return 0;
}
