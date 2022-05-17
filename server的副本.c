#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define MAX_REQUEST_SIZE 2048
#define BACKLOG 100

#define IMPLEMENTS_IPV6

#define MULTITHREADED

int socket_open_bind_listen(char *port_number_string, int protocl_type)
{
    struct addrinfo *info, *pinfo;
    struct addrinfo hint;
    memset(&hint, 0, sizeof hint);
    hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_family = AF_UNSPEC;
    int rc = getaddrinfo(NULL, port_number_string, &hint, &info);
    if (rc != 0)
    {
        return -1;
    }

    struct addrinfo *selected_info = NULL;
    char printed_addr[1024];
    for (pinfo = info; pinfo; pinfo = pinfo->ai_next)
    {
        rc = getnameinfo(pinfo->ai_addr, pinfo->ai_addrlen,
                         printed_addr, sizeof printed_addr, NULL, 0,
                         NI_NUMERICHOST);
        if (rc != 0)
        {
            perror("getnameinfo");
            return -1;
        }

        // use ipv6
        if (protocl_type == 6 && pinfo->ai_family == AF_INET6)
        {
            selected_info = pinfo;
            break;
        }
        else if (protocl_type == 4 && pinfo->ai_family == AF_INET)
        {
            // user ipv4
            selected_info = pinfo;
            break;
        }
    }

    // create server socket
    if (selected_info)
    {
        int s = socket(selected_info->ai_family, selected_info->ai_socktype, selected_info->ai_protocol);
        if (s == -1)
        {
            perror("socket");
            return -1;
        }

        int opt = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        rc = bind(s, selected_info->ai_addr, selected_info->ai_addrlen);
        if (rc == -1)
        {
            perror("bind");
            close(s);
            return -1;
        }

        rc = listen(s, BACKLOG);
        if (rc == -1)
        {
            perror("listen");
            close(s);
            return -1;
        }

        freeaddrinfo(info);
        return s;
    }

    fprintf(stderr, "No suitable address to bind port %s found\n", port_number_string);
    return -1;
}

int socket_accept_client(int server_socket)
{
    struct sockaddr_storage peer;
    socklen_t peersize = sizeof(peer);

    int client = accept(server_socket, (struct sockaddr *)&peer, &peersize);
    if (client == -1)
    {
        perror("accept");
        return -1;
    }

    int i = 1;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i));
    return client;
}

void readline(int socket, char *line)
{
    char *ptr = line;
    while (1)
    {
        // read from the socket
        read(socket, ptr, 1);

        // must read the \r\n\r\n in case of client stall
        if (strlen(line) > 4 && strcmp(line + strlen(line) - 4, "\r\n\r\n") == 0)
        {
            break;
        }

        ptr++;
    }
}

const char *get_mime_by_name(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "application/octet-stream";

    if (!strcasecmp(suffix, ".css"))
        return "text/css";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";

    return "application/octet-stream";
}

void *process_request(void *arg)
{
    int socket = (int)(long)arg;
    // read the request line by line
    char line[MAX_REQUEST_SIZE];
    memset(line, 0, sizeof(line));

    // read the protocl line
    readline(socket, line);

    // parse the protocol
    char request_type[64];
    memset(request_type, 0, sizeof(request_type));
    char request_path[128];
    memset(request_path, 0, sizeof(request_path));
    char request_protocol[64];
    memset(request_protocol, 0, sizeof(request_protocol));

    char response_header[128];
    // bad request
    int scan_num = sscanf(line, "%s %s %s\r\n", request_type, request_path, request_protocol);
    if (scan_num != 3 || strcmp(request_type, "GET"))
    {
        sprintf(response_header, "HTTP/1.0 %d %s\r\n\r\n", 400, "Bad Request");
        write(socket, response_header, strlen(response_header));
        close(socket);
        return NULL;
    }

    // remove / in begin of path
    char *filepath = &request_path[0] + 1;

    // check if the file existed
    if (access(filepath, R_OK) < 0)
    {
        sprintf(response_header, "HTTP/1.0 %d %s\r\n\r\n", 404, "File Not Found");
        write(socket, response_header, strlen(response_header));
        close(socket);
        return NULL;
    }

    // send the response header
    sprintf(response_header, "HTTP/1.0 %d %s\r\n", 200, "OK");
    write(socket, response_header, strlen(response_header));

    // send file
    int file_fd = open(filepath, O_RDONLY);
    struct stat stat;
    memset(&stat, 0, sizeof(stat));

    // get file info
    fstat(file_fd, &stat);

    // send the file back
    const char *mime_type = get_mime_by_name(filepath);
    // set content type
    char header_line[128];
    sprintf(header_line, "Content-Type: %s\r\n", mime_type);
    write(socket, header_line, strlen(header_line));
    // set content length
    sprintf(header_line, "Content-Length: %ld\r\n\r\n", stat.st_size);
    write(socket, header_line, strlen(header_line));

    /**
     * Use sendfile to encapsulate the process of reading data from the source fd and writing to the destination fd,
     * and does not require the caller to create a buffer to read data.
     * And sendfile copies data in kernelspace through fd, which is more efficient than read/write, 
     * because read needs to copy data from kernelspace to userspace 
     * and then write to copy data from userspace to kernelspace
     */
    sendfile(socket, file_fd, 0, stat.st_size);

    close(file_fd);
    close(socket);

    return NULL;
}

int main(int argc, char **argv)
{
    // check input arguments
    int protocol = atoi(argv[1]);
    if (protocol != 4 && protocol != 8)
    {
        return 1;
    }
    
    char *port_str = argv[2];
    if (atoi(port_str) <= 0)
    {
        return 1;
    }
    
    // change current dir to webroot
    char *web_root = argv[3];
    if (chdir(web_root) < 0)
    {
        return 1;
    }

    // create the server socket
    int server_socket = socket_open_bind_listen(port_str, protocol);
    if (server_socket < 0)
    {
        return 1;
    }
    
    while (1)
    {
        // waiting for a client
        int client = socket_accept_client(server_socket);
        if (client < 0)
        {
            continue;
        }
        
        // process request from client in a thread
        pthread_t pid;
        pthread_create(&pid, NULL, process_request, (void *)(long)client);
    }

    return 0;
}
