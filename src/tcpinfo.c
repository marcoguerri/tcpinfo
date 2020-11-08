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
#include <errno.h>
#include <string.h>
#include <dlfcn.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include "libll/ll.h"
#include "config.h"

#ifdef DEBUG
#define debug(fmt, ...) \
        fprintf(stderr, "%s: " fmt, __func__, ##__VA_ARGS__)
#else
#define debug(fmt, ...) {}
#endif

ll_t* list_sock = NULL;

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


/* Helper struct which maps a tcpinfo struct to the respective file descriptor */
struct tcpinfo_fd_pair
{
    int sock_fd;
    struct tcp_info tcpinfo;
};


struct tpcinfo_field tcpinfo_fields_enabled[] =
{
#ifdef HAVE_STRUCT_TCP_INFO_TCPI_STATE
    ENABLE_FIELD(state, "hhu"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_CA_STATE
    ENABLE_FIELD(ca_state, "hhu"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_RETRANSMITS
    ENABLE_FIELD(retransmits, "hhu"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_PROBES
    ENABLE_FIELD(probes, "hhu"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_BACKOFF
    ENABLE_FIELD(backoff, "hhu"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_OPTIONS
    ENABLE_FIELD(options, "hhu"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_RTO
    ENABLE_FIELD(rto, "u"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_LOST
    ENABLE_FIELD(lost, "u"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_RETRANS
    ENABLE_FIELD(retrans, "u"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_TOTAL_RETRANS
    ENABLE_FIELD(total_retrans, "u"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_ADVMSS
    ENABLE_FIELD(advmss, "u"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_ATO
    ENABLE_FIELD(ato, "u"),
#endif

#ifdef HAVE_STRUCT_TCP_INFO_TCPI_FACKETS
    ENABLE_FIELD(fackets, "u")
#endif
};

void print_summary_sockets(ll_t* list_tcp_info)
{
    /*
     * One remark before everything else: some of these counters are reset
     * farily often (e.g. retrans or lost), therefore they do not account for
     * all the actual events. One possible solution is to define a sampling rate
     * and keep track of a cumulative counter. Of course this would not account
     * for all the real events either, but would give an idea of the number of
     * events integrated over time.
     */
    if(ll_len(list_tcp_info) == 0) {
        return;
    }
    uint32_t i = 0, j = 0;
    uint8_t num_fields;
    char fmt[10];
    struct tcpinfo_fd_pair *p;

    fprintf(stderr, "%15s", "fd");
    for(i = 0; i < ll_len(list_tcp_info); ++i)
    {
        p = (struct tcpinfo_fd_pair*)(ll_node_get(list_tcp_info, i)->data->payload);
        fprintf(stderr, "%15d", p->sock_fd);
    }
    fprintf(stderr, "\n");
    num_fields = sizeof(tcpinfo_fields_enabled)/sizeof(tcpinfo_fields_enabled[0]);

    for(i = 0; i < num_fields; i++)
    {
        fprintf(stderr, "%15s", tcpinfo_fields_enabled[i].name);
        for(j = 0; j < ll_len(list_tcp_info); ++j)
        {
            struct tcpinfo_fd_pair *p = ll_node_get(list_tcp_info, j)->data->payload;
            sprintf(fmt, "%%15%s", tcpinfo_fields_enabled[i].fmt);
            uint8_t *ptr_field = (uint8_t*)&(p->tcpinfo) + tcpinfo_fields_enabled[i].offset;
            fprintf(stderr, fmt, *((uint32_t*)ptr_field));
        }
        fprintf(stderr, "\n");
     }
    fprintf(stderr, "\n");
}

void sigusr_callback(int signum)
{

    struct tcp_info tcp_info;
    int sock_fd;
    uint32_t i = 0;

    /* List of tcp_info structures with corresponding fds */
    ll_t* list_tcp_info = NULL;
    struct tcpinfo_fd_pair p;

    socklen_t tcp_info_len = sizeof(struct tcp_info);
    size_t num_sockets = ll_len(list_sock);

    if(num_sockets > 0) {
        sock_fd = *((int*)ll_node_get(list_sock, i)->data->payload);
        int ret = getsockopt(sock_fd, IPPROTO_TCP, TCP_INFO,
                            (void *)&tcp_info, &tcp_info_len);

        if(ret < 0)
        {
            debug("could not get TCP_INFO for socket %d\n", sock_fd);
            perror("");
        } else {
            debug("retrieved tcp info for %d\n", sock_fd);

            /* Snapshot of tcp_info structure obtained from the kernel */
            memcpy(&p.tcpinfo, &tcp_info, sizeof(struct tcp_info));
            p.sock_fd = sock_fd;
            list_tcp_info = ll_init(&p, sizeof(struct tcpinfo_fd_pair));
        }
    }

    debug("number of fds in list: %lu\n",ll_len(list_sock));
    for(i = 1; i < num_sockets; ++i )
    {
        sock_fd = *((int*)ll_node_get(list_sock, i)->data->payload);
        int ret = getsockopt(sock_fd, IPPROTO_TCP, TCP_INFO,
                            (void *)&tcp_info, &tcp_info_len);

        if(ret < 0)
        {
            debug("could not get TCP_INFO for socket %d\n", sock_fd);
            continue;
        }
        debug("got TCP_INFO for %d\n", sock_fd);

        /* Snapshot of tcp_info structure obtained from the kernel */
        memcpy(&p.tcpinfo, &tcp_info, sizeof(struct tcp_info));
        p.sock_fd = sock_fd;
        /* Adding the new pair <fd,tcp_info> to the list */
        list_tcp_info = ll_insert(list_tcp_info, &p,
                                        ll_len(list_tcp_info));

    }
    print_summary_sockets(list_tcp_info);
    ll_destroy(list_tcp_info);
}

__attribute__((constructor))
void init_preload()
{

    /* Install handler for SIGUSR1 */
    struct sigaction sigusr_action;
    sigusr_action.sa_handler = &sigusr_callback;
    /*
     * Setting a handler for SIGUSR1, specifying SA_RESTART to restart syscalls.
     * In some cases, this is not enough. For instance, poll is never restarted
     * if interrupted, regardless of SA_RESTART. If the any of the two ends of the
     * communication is polling, upon receiving SIGUSR it will return
     * with EINTR and it will most likely exit. A hook for poll is set to restart
     * the call when EINTR is returned.
     */
    sigusr_action.sa_flags = SA_RESTART;
    
    int (*sigaction_libc)(int, const struct sigaction*, struct sigaction*);
    sigaction_libc = (int(*)(int, const struct sigaction*, struct sigaction*))dlsym(RTLD_NEXT, "sigaction");
 
    if((*sigaction_libc)(SIGUSR1, &sigusr_action, NULL) < 0)
        debug("could not install SIGUSR1 signal\n");
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    /* poll hook which restarts the system call upon receiving a signal.
     * poll normally returns always EINTR when interrupted even if SA_RESTART
     * is set. The this will restart poll until some != from EINTR is returned */

    int (*poll_libc)(struct pollfd*, nfds_t, int);
    poll_libc = (int(*)(struct pollfd *, nfds_t, int))dlsym(RTLD_NEXT, "poll");

    int ret = (*poll_libc)(fds, nfds, timeout);
    while(ret == -1 && errno == EINTR)
        ret = (*poll_libc)(fds, nfds, timeout);

    return ret;
}

int socket(int domain, int type, int protocol)
{
    
    int (*socket_libc)(int, int, int);
    socket_libc = (int(*)(int, int, int))dlsym(RTLD_NEXT, "socket");
    int fd = (*socket_libc)(domain, type, protocol);

    /* Consider only AF_INET and SOCK_STREAM sockets */
    if( (domain != AF_INET && domain != AF_INET6) ||  type != SOCK_STREAM || fd < 0)
    {
        debug("ignoring file descriptor %d\n", fd);
        return fd;
    }
    pid_t pid = getpid();
    debug("ignoring welcoming socket %d, pid: %d\n", fd, pid);
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

    if(fd > 0)
    {
        if(!list_sock) {
            list_sock = ll_init(&fd, sizeof(int));
        } else {
            pid_t pid = getpid();
            debug("adding file descriptor %d, pid: %d\n", fd, pid);
            ll_insert(list_sock, &fd, ll_len(list_sock));
       }
    }
    return fd;
}


int close(int fd)
{
    int (*close_libc)(int);
    struct stat statbuf;

    close_libc = (int(*)(int))dlsym(RTLD_NEXT, "close");
    int ret = (*close_libc)(fd);
    if(list_sock != NULL)
    {
        /* fd might not be a socket. If it's indeed a socket, it might  have been
         * ignored because != SOCK_STREAM and AF_INET */
        fstat(fd, &statbuf);
        if(S_ISSOCK(statbuf.st_mode)) 
        {
            debug("deleting file descriptor %d\n", fd);
            ll_del(list_sock, &fd);
        }
    }
    return ret;
}

/* If process tries to SIG_IGN or SIG_DFL SIGUSR1, then ignore */
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{

    int ret;
    int (*sigaction_libc)(int, const struct sigaction*, struct sigaction*);
    sigaction_libc = (int(*)(int, const struct sigaction*, struct sigaction*))dlsym(RTLD_NEXT, "sigaction");
    
    if(signum == SIGUSR1 && act != NULL &&
       (act->sa_handler == SIG_IGN || act->sa_handler == SIG_DFL))
    {
        debug("ignoring request to set SIGUSR1 to SIG_IGN or SIG_DFL\n");
        return 0;
    }
    
    ret = (*sigaction_libc)(signum, act, oldact);
    return ret;
}
