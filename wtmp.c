/*
 * This plugin logs connections to wtmp.
 *
 * Copyright (C) 2015 Eurotux Informática S.A.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <utmp.h>

#include "openvpn-plugin.h"

#define COMMAND_LOG_CONN              10
#define COMMAND_LOG_DISCONN           11
#define COMMAND_EXIT                  12
#define BACKGROUND_INIT_SUCCEEDED     13
#define BACKGROUND_COMMAND_SUCCEEDED  14
#define RECV_ERROR                   -10
#define SEND_ERROR                   -11
#define BACKGROUND_COMMAND_FAILED    -12

/*
 * Our plugin context, where we keep our state.
 */
struct plugin_context {
    int total_clients; /* number of clients connected */
    int foreground_fd;
    pid_t background_pid;
};

/*
 * Each of the client's context.
 */
struct plugin_per_client_context {
    char *line; /* line entry for the wtmp file */
    char *username;
    char *source_address;
};

/*
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 *
 * Taken from the OpenVPN sample plugins source code,
 * distributed with the source code of the 2.3.6
 * version of OpenVPN (src/plugins/down-root/down-root.c)
 */
static const char *
get_env(const char *name,
        const char *envp[]) {
    if (envp) {
        int i;
        const int namelen = strlen(name);
        for (i = 0; envp[i]; ++i) {
            if (!strncmp(envp[i], name, namelen)) {
                const char *cp = envp[i] + namelen;
                if (*cp == '=')
                    return cp + 1;
            }
        }
    }
    
    return NULL;
}

/*
 * Receives and return a control command
 * from the given file descriptor.
 * 
 * Adapted from the OpenVPN sample plugins source code,
 * distributed with the source code of the 2.3.6
 * version of OpenVPN (src/plugins/down-root/down-root.c)
 */
static int
recv_control(int fd) {
    unsigned char c;
    const ssize_t size = read(fd, &c, sizeof(c));
    if (size == sizeof(c))
        return c;
    else
        return RECV_ERROR;
}

/*
 * Sends a control command to the given
 * file descriptor.
 *
 * Adapted from the OpenVPN sample plugins source code,
 * distributed with the source code of the 2.3.6
 * version of OpenVPN (src/plugins/down-root/down-root.c)
 */
static int
send_control(int fd, int code) {
    unsigned char c = (unsigned char)code;
    const ssize_t size = write(fd, &c, sizeof(c));
    if (size == sizeof(c))
        return (int)size;
    else
        return SEND_ERROR;
}

/*
 * Receives a string from the given
 * file descriptor.
 */
char *
recv_str(int fd) {
    int len;
    char *str;
    ssize_t size = read(fd, &len, sizeof(int));
    if (size <= 0)
        return NULL;
    else{
        str = (char *)calloc(len, sizeof(char));
        size = read(fd, str, len);
        
        return str;
    }
}

/*
 * Sends a string to the given
 * file descriptor.
 */
static int
send_str(int fd, const char *string) {
    int len = strlen(string) + 1;
    ssize_t size = write(fd, &len, sizeof(int));
    if (size <= 0)
        return SEND_ERROR;
    else {
        size = write(fd, string, len);
        
        if (size == len)
            return (int)size;
        else
            return SEND_ERROR;
    }
}

/*
 * Logs a message to stderr.
 */
void
log_message(const char *message) {
    fprintf(stderr, "WTMP_PLUGIN: %s\n", message);
}

/*
 * Daemonize if "daemon" env var is true.
 * Preserve stderr across daemonization if
 * "daemon_log_redirect" env var is true.
 *
 * Adapted from the OpenVPN sample plugins source code,
 * distributed with the source code of the 2.3.6
 * version of OpenVPN (src/plugins/down-root/down-root.c)
 */
static void
daemonize(const char *envp[]) {
    const char *daemon_string = get_env("daemon", envp);
    if (daemon_string && daemon_string[0] == '1') {
        const char *log_redirect = get_env("daemon_log_redirect", envp);
        int fd = -1;
        
        if (log_redirect && log_redirect[0] == '1')
            fd = dup(2);
        
        if (daemon(0, 0) < 0) {
            log_message("ERROR: daemonization failed");
        } else if (fd >= 3) {
            dup2(fd, 2);
            close(fd);
        }
    }
}


/*
 * Background process main loop.
 */
void
background_listen(const int background_fd) {
    log_message("BACKGROUND PROCESS: initiated");
    
    if (send_control(background_fd, BACKGROUND_INIT_SUCCEEDED) == SEND_ERROR) {
        log_message("BACKGROUND PROCESS: write error to main process'"
                    "file descriptor");
        exit(-1);
    }
    
    while(1) {
        int command;
        int status;
        
        char *line, *username, *source_address;
        
        command = recv_control(background_fd);
        
        switch (command) {
            case COMMAND_LOG_CONN:
                log_message("BACKGROUND PROCESS: connection");
                
                line = recv_str(background_fd);
                username = recv_str(background_fd);
                source_address = recv_str(background_fd);
                
                logwtmp(line, username, source_address);
                
                free(line);
                free(username);
                free(source_address);
                
                status = BACKGROUND_COMMAND_SUCCEEDED;
                break;
            case COMMAND_LOG_DISCONN:
                log_message("BACKGROUND PROCESS: disconnection");
                
                line = recv_str(background_fd);
                
                logwtmp(line, "", "");
                
                free(line);
                
                status = BACKGROUND_COMMAND_SUCCEEDED;
                break;
            case COMMAND_EXIT:
                log_message("BACKGROUND PROCESS: exit");
                close(background_fd);
                exit(0);
            case RECV_ERROR:
                log_message("BACKGROUND PROCESS: error");
                status = BACKGROUND_COMMAND_FAILED;
                break;
            default:
                log_message("BACKGROUND PROCESS: error");
                status = BACKGROUND_COMMAND_FAILED;
                break;
        }
        
        if (send_control(background_fd, status) == SEND_ERROR) {
            log_message("BACKGROUND PROCESS: write error to "
                        "main process' file descriptor");
            exit(-1);
        }
    }
}

/*
 * Logs a connection of a client
 * to the wtmp file.
 */
OPENVPN_EXPORT int
log_connection(struct plugin_context *context,
               struct plugin_per_client_context *client_context,
               const char *envp[]) {
    char *line, *message;
    const char *interface = (char *)get_env("dev", envp);
    const char *username = get_env("username", envp);
    const int id = context->total_clients;
    
    if (asprintf(&line, "%s/%d", interface, id) == -1) {
        log_message("ERROR: insufficient memory");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    /* if there's no username set use the
       common name of the client */
    if (!username) {
        username = (char *)get_env("common_name", envp);
    }
    
    client_context->line = line;
    client_context->username = (char *)username;
    client_context->source_address = (char *)get_env("trusted_ip", envp);
    
    if (asprintf(&message,
                 "CLIENT CONNECTED (line=%s, username=%s, source_address=%s)",
                 client_context->line,
                 client_context->username,
                 client_context->source_address) == -1) {
        log_message("ERROR: insufficient memory");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    log_message(message);
    
    /* send message to child process to write to wtmp file */
    send_control(context->foreground_fd, COMMAND_LOG_CONN);
    
    send_str(context->foreground_fd, client_context->line);
    send_str(context->foreground_fd, client_context->username);
    send_str(context->foreground_fd, client_context->source_address);
    
    /* receive status code from child process */
    int status = recv_control(context->foreground_fd);
    
    switch (status) {
        case BACKGROUND_COMMAND_FAILED:
            log_message("ERROR: background connection command failed");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        case RECV_ERROR:
            log_message("ERROR: communication with background process failed");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        default:
            break;
    }
    
    context->total_clients++;
    
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/*
 * Logs a disconnection of a client
 * to the wtmp file.
 */
OPENVPN_EXPORT int
log_disconnection(struct plugin_context *context,
                  struct plugin_per_client_context *client_context) {
    char *message;
    
    if (asprintf(&message,
                 "CLIENT DISCONNECTED (line=%s, username=%s, source_address=%s)",
                 client_context->line,
                 client_context->username,
                 client_context->source_address) == -1) {
        log_message("ERROR: insufficient memory");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    log_message(message);
    
    /* send message to child process to write to wtmp file */
    send_control(context->foreground_fd, COMMAND_LOG_DISCONN);
    
    send_str(context->foreground_fd, client_context->line);
    
    /* receive status code from child process */
    int status = recv_control(context->foreground_fd);
    
    switch (status) {
        case BACKGROUND_COMMAND_FAILED:
            log_message("ERROR: background connection command failed");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        case RECV_ERROR:
            log_message("ERROR: communication with background process failed");
            return OPENVPN_PLUGIN_FUNC_ERROR;
        default:
            break;
    }
    
    context->total_clients--;
    
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/*
 * Initialization of a client context.
 */
OPENVPN_EXPORT void *
openvpn_plugin_client_constructor_v1(openvpn_plugin_handle_t handle) {
    return calloc(1, sizeof(struct plugin_per_client_context));
}

/*
 * Destruction of a client context.
 */
OPENVPN_EXPORT void
openvpn_plugin_client_destructor_v1(openvpn_plugin_handle_t handle,
                                    void *per_client_context) {
    struct plugin_per_client_context *pcc =
        (struct plugin_per_client_context *)per_client_context;
    free(pcc->line);
    free(pcc);
}

/*
 * Initialization of the plugin.
 */
OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1(unsigned int *type_mask,
                       const char *argv[],
                       const char *envp[]) {
    struct plugin_context *context;
    
    /* allocate our context */
    context = (struct plugin_context *)calloc(1, sizeof(struct plugin_context));
    
    if (!context) {
        log_message("ERROR: could not allocate memory for plugin context");
        return NULL;
    }
    
    context->total_clients = 0;
    context->foreground_fd = -1;
    
    /* which callbacks to intercept */
    *type_mask = OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_CLIENT_CONNECT_V2) |
                 OPENVPN_PLUGIN_MASK (OPENVPN_PLUGIN_CLIENT_DISCONNECT);
    
    /* create the child process tp retain root access */
    if (context->foreground_fd == -1) {
        pid_t pid;
        int fd[2];
        
        /* create a socket for foreground and
           background processes communicate. */
        if (socketpair(PF_UNIX, SOCK_DGRAM, 0, fd) == -1) {
            log_message("ERROR: socketpair failed");
            exit(-1);
        }
        
        context->foreground_fd = fd[0];
        
        pid = fork();
        
        if (pid == -1) {
            log_message("ERROR: couldn't create a child process'");
            exit(-1);
        } else if (pid) {
            /* foreground process */
            int status;
            
            context->background_pid = pid;
            
            /* close the child file descriptor */
            close(fd[1]);
            
            status = recv_control(fd[0]);
            
            if (status == BACKGROUND_INIT_SUCCEEDED) {
                context->foreground_fd = fd[0];
            } else {
                log_message("ERROR: couldn't create a child process");
                close(fd[0]);
                exit(-1);
            }
        } else {
            /* background process */
            
            /* close the parent file descriptor */
            close(fd[0]);
            
            /* ignore signals which should be
               handled by the parent */
            signal(SIGINT, SIG_IGN);
            signal(SIGHUP, SIG_IGN);
            signal(SIGUSR1, SIG_IGN);
            signal(SIGUSR2, SIG_IGN);
            signal(SIGPIPE, SIG_IGN);
            
            daemonize(envp);
            
            /* main loop */
            background_listen(fd[1]);
            
            close(fd[1]);
        }
    }
    
    return (openvpn_plugin_handle_t)context;
}

/*
 * Handler for the callbacks.
 */
OPENVPN_EXPORT int
openvpn_plugin_func_v2(openvpn_plugin_handle_t handle,
                       const int type,
                       const char *argv[],
                       const char *envp[],
                       void *per_client_context,
                       struct openvpn_plugin_string_list **return_list) {
    struct plugin_context *context = (struct plugin_context *) handle;
    
    switch (type) {
        case OPENVPN_PLUGIN_CLIENT_CONNECT_V2:
            return log_connection(context, per_client_context, envp);
        case OPENVPN_PLUGIN_CLIENT_DISCONNECT:
            return log_disconnection(context, per_client_context);
        default:
            break;
    }
    
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

/*
 * Closing the plugin.
 */
OPENVPN_EXPORT void
openvpn_plugin_close_v1(openvpn_plugin_handle_t handle) {
    struct plugin_context *context = (struct plugin_context *)handle;
    
    if (context->foreground_fd >= 0) {
        send_control(context->foreground_fd, COMMAND_EXIT);
        
        if (context->background_pid > 0)
            waitpid(context->background_pid, NULL, 0);
        
        close(context->foreground_fd);
        context->foreground_fd = -1;
    }
    
    free((struct plugin_context *)handle);
}

/*
 * Aborting the plugin.
 */
OPENVPN_EXPORT void
openvpn_plugin_abort_v1(openvpn_plugin_handle_t handle) {
    struct plugin_context *context = (struct plugin_context *)handle;
    
    if (context && context->foreground_fd >= 0) {
        send_control(context->foreground_fd, COMMAND_EXIT);
        close(context->foreground_fd);
        context->foreground_fd = -1;
    }
}
