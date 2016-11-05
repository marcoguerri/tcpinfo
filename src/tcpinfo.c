/*
 * The MIT License (MIT)
 * Copyright (C) 2016 Marco Guerri
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of 
 * this software and associated documentation files (the "Software"), to deal in 
 * the Software without restriction, including without limitation the rights to use, 
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
 * Software, and to permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include "list.h"

list_node_t* list_sock = NULL;

#define STRLEN(s) (sizeof(s)/sizeof(s[0]))
#define ENABLE_FIELD(f, fmt) {#f, fmt, offsetof(struct tcp_info, tcpi_##f)} 
struct tpcinfo_field 
{
    /* Name of the field of interest */
    char *name;
    /* Format string without % */
    char fmt[4];
    /* Offset within tcp_info */
    unsigned int offset;
};

struct tpcinfo_field tcpinfo_fields_enabled[] = 
{
    ENABLE_FIELD(state, "hhu"),
    ENABLE_FIELD(ca_state, "hhu"),
    ENABLE_FIELD(retransmits, "hhu"),
    ENABLE_FIELD(probes, "hhu"),
    ENABLE_FIELD(backoff, "hhu"),
    ENABLE_FIELD(options, "hhu"),
    ENABLE_FIELD(rto, "u"),
    ENABLE_FIELD(lost, "u"),
    ENABLE_FIELD(retrans, "u"),
    ENABLE_FIELD(total_retrans, "u"),
    ENABLE_FIELD(advmss, "u"),
    ENABLE_FIELD(ato, "u"),
    ENABLE_FIELD(fackets, "u")
};



void print_summary_header()
{
    uint32_t i = 0;
    char *fmt;
    fprintf(stdout, "%5s", "fd");
    
    fmt = (char*) malloc(sizeof(char) * 50);
    if(fmt == NULL) 
    {
        perror("malloc");
        exit(1);
    }

    for(; i < sizeof(tcpinfo_fields_enabled)/sizeof(tcpinfo_fields_enabled[0]); i++) 
    {
        sprintf(fmt, "%%%zus", strlen(tcpinfo_fields_enabled[i].name) + 5);
        fprintf(stdout, fmt, tcpinfo_fields_enabled[i].name);

    }
    fprintf(stdout,"\n");
    free(fmt);
}

void print_summary_socket(int sock_fd, struct tcp_info* tcpinfo)
{
    /*
     * One remark before everything else: some of these counters are reset
     * farily often (e.g. retrans or lost), therefore they do not account for
     * all the actual events. One possible solution is to define a sampling rate
     * and keep track of a cumulative counter. Of course this would not account
     * for all the real events either, but would give an idea of the number of
     * events integrated over time. 
     * 
     * Follows an attempt to explain the meaning of each field.
     * advmss:   the MSS ('Maximal Segment Size') supported by the connection. 
     *           Linux uses a default value calculated from the first hop device MTU. 
     * ato:      ACK timeout, timeout period for sending a delayed ack, relevant
     *           when delaying ACKs in order to group them together. Controller by
     *           /proc/sys/net/ipv4/tcp_ato_min
     * backoff:  TCP exponential backoff strategy?
     * ca_state: Current state of the FSA which controls the TCP congestion algorithm
     * fackets:  What the hell is this? 
     *
     */
    uint32_t i = 0;
    char *fmt;

    fprintf(stdout, "%5d", sock_fd);
    fmt = (char*) malloc(sizeof(char) * 50);
    for(; i < sizeof(tcpinfo_fields_enabled)/sizeof(tcpinfo_fields_enabled[0]); i++)
    { 
        sprintf(fmt, "%%%zu%s", 
                strlen(tcpinfo_fields_enabled[i].name) + 5,
                tcpinfo_fields_enabled[i].fmt);
        uint8_t *ptr_field = (uint8_t*)tcpinfo + tcpinfo_fields_enabled[i].offset;
        fprintf(stdout, fmt, *((uint32_t*)ptr_field));
    }
    fprintf(stdout, "\n");
    free(fmt);

}

void sigusr_callback(int signum)
{

    struct tcp_info tcp_info;
    int sock_fd;
    uint32_t index = 0;
    
    socklen_t tcp_info_len = sizeof(struct tcp_info);
    if(list_len(list_sock) == 0)
    {
        fprintf(stderr, "No active sockets\n");
        return;
    }

    size_t num_sockets = list_len(list_sock);
    for(; index < num_sockets; index++ )
    {
        sock_fd = *((int*)list_get(list_sock, 0));
        int ret = getsockopt(sock_fd, 
                             IPPROTO_TCP,
                             TCP_INFO,
                             (void *)&tcp_info,
                             &tcp_info_len);

        print_summary_header();

        if(ret == 0) 
            print_summary_socket(sock_fd, &tcp_info);
        else 
            fprintf(stderr, "Error querying TCP_INFO\n");
    }

}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    /* poll hack to make it restart upon returning with EINTR. If poll
     * is interrupted twice, the second interruption will not be trapped */
    int (*poll_libc)(struct pollfd*, nfds_t, int);
    poll_libc = (int(*)(struct pollfd *, nfds_t, int))dlsym(RTLD_NEXT, "poll");
    
    int ret = (*poll_libc)(fds, nfds, timeout);
    if(ret == -1 && errno == EINTR)
        ret = (*poll_libc)(fds, nfds, timeout);

    return ret;
}

int socket(int domain, int type, int protocol)
{
    struct sigaction sigusr_action;
    sigusr_action.sa_handler = &sigusr_callback;
    /* 
     * Setting handler for SIGUSR1, specifying SA_RESTART to restart syscalls.
     * In some cases, this is not enough. For instance, poll is never restarted 
     * if interrupted, regardless of SA_RESTART. If the any of the two ends of the
     * communication is polling, upon receiving SIGUSR it will will return
     * with EINTR and it will most likely exit. A hook for poll is set to work 
     * around this issue.
     */
    sigusr_action.sa_flags = SA_RESTART;
   
    struct sigaction old_action; 
    int ret = sigaction(SIGUSR1, NULL, &old_action);
    if(ret < 0) 
    {
        /* Cannot verify if the signal is installed. Forcing installation */
        if(sigaction(SIGUSR1, &sigusr_action, NULL) < 0)
            fprintf(stderr,"Could not install SIGUSR1 signal\n");
    }
    else
    {
        if(old_action.sa_handler != &sigusr_callback)    
        {
            /* Signal handler has not been installed yet */
            if(sigaction(SIGUSR1, &sigusr_action, NULL) < 0)
            {
                fprintf(stderr,"Could not install SIGUSR1 signal\n");
            }
            else 
            {
                fprintf(stderr,"Signal handler installed correctly\n");
                pid_t pid = getpid();
                fprintf(stderr, "Signal PID %d to obtain tcp socket info\n", pid);
            }
            
        }
    }
    
    int (*socket_libc)(int, int, int);
    socket_libc = (int(*)(int, int, int))dlsym(RTLD_NEXT, "socket");
    int fd = (*socket_libc)(domain, type, protocol);
    
    /* Consider only AF_INET and SOCK_STREAM sockets */
    if( (domain != AF_INET && domain != AF_INET6) ||  type != SOCK_STREAM)
        return fd;
 
    if(list_sock == NULL)
        list_sock = list_init(&fd, sizeof(int));
    else
        list_sock = list_insert(list_sock, &fd, sizeof(int), list_len(list_sock)); 

    return fd;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    
    int (*accept_libc)(int, struct sockaddr*, socklen_t*);
    accept_libc = (int(*)(int, struct sockaddr*, socklen_t*))dlsym(RTLD_NEXT, "accept");
    
    int fd = (*accept_libc)(sockfd, addr, addrlen);
 
    /* Calling accept on socketfd requires having previously called socket(),
     * which initializes the list. If list is indeed NULL, accept is being called
     * on a socket which has not been initialized or on a socket != AF_INET | AF_INET6
     * and SOCK_STREAM. Do nothing in this case */

    if(list_sock != NULL)
    {
        if(list_search(list_sock, &sockfd, sizeof(int)) == NULL) 
        {
            /* Welcoming socket must be already in the list. If not, warn but
             * add the new socket anyway */
            fprintf(stderr, "Welcoming socket is not in the list?\n");
        }
        list_sock = list_insert(list_sock, &fd, sizeof(int), list_len(list_sock)); 
    }
 
    return fd;
}


int close(int fd)
{
    int (*close_libc)(int);
    close_libc = (int(*)(int))dlsym(RTLD_NEXT, "close");
    int ret = (*close_libc)(fd);
    if(list_sock != NULL)
        list_sock = list_del(list_sock, &fd, sizeof(int));

    return ret;
}

