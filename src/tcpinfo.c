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
#include <dlfcn.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <poll.h>
#include <errno.h>

#include "list.h"

node_t* list_sock = NULL;


void sigusr_callback(int signum)
{

    struct tcp_info tcp_info;
    socklen_t tcp_info_len = sizeof(struct tcp_info);
    if(list_len(list_sock) == 0)
    {
        fprintf(stderr, "No active sockets\n");
        return;
    }
    int sock_fd = *((int*)list_get(list_sock, 0));

    int ret = getsockopt(sock_fd, 
                         IPPROTO_TCP,
                         TCP_INFO,
                         (void *)&tcp_info,
                         &tcp_info_len);
    if(ret == 0) 
    {
        fprintf(stderr, "\n\nsocket %d %ld\n", sock_fd, sizeof(tcp_info));
        fprintf(stderr, "          state: %lu\n", (unsigned long) tcp_info.tcpi_state);
        fprintf(stderr, "       ca_state: %lu\n", (unsigned long) tcp_info.tcpi_ca_state);
        fprintf(stderr, "    retransmits: %lu\n", (unsigned long) tcp_info.tcpi_retransmits);
        fprintf(stderr, "         probes: %lu\n", (unsigned long) tcp_info.tcpi_probes);
        fprintf(stderr, "        backoff: %lu\n", (unsigned long) tcp_info.tcpi_backoff);
        fprintf(stderr, "        options: %lu\n", (unsigned long) tcp_info.tcpi_options);
        fprintf(stderr, "     snd_wscale: %lu\n", (unsigned long) tcp_info.tcpi_snd_wscale);
        fprintf(stderr, "     rcv_wscale: %lu\n", (unsigned long) tcp_info.tcpi_rcv_wscale);
        fprintf(stderr, "            rto: %lu\n", (unsigned long) tcp_info.tcpi_rto);
        fprintf(stderr, "            ato: %lu\n", (unsigned long) tcp_info.tcpi_ato);
        fprintf(stderr, "        snd_mss: %lu\n", (unsigned long) tcp_info.tcpi_snd_mss);
        fprintf(stderr, "        rcv_mss: %lu\n", (unsigned long) tcp_info.tcpi_rcv_mss);
        fprintf(stderr, "        unacked: %lu\n", (unsigned long) tcp_info.tcpi_unacked);
        fprintf(stderr, "         sacked: %lu\n", (unsigned long) tcp_info.tcpi_sacked);
        fprintf(stderr, "           lost: %lu\n", (unsigned long) tcp_info.tcpi_lost);
        fprintf(stderr, "        retrans: %lu\n", (unsigned long) tcp_info.tcpi_retrans);
        fprintf(stderr, "        fackets: %lu\n", (unsigned long) tcp_info.tcpi_fackets);
        fprintf(stderr, " last_data_sent: %lu\n", (unsigned long) tcp_info.tcpi_last_data_sent);
        fprintf(stderr, "  last_ack_sent: %lu\n", (unsigned long) tcp_info.tcpi_last_ack_sent);
        fprintf(stderr, " last_data_recv: %lu\n", (unsigned long) tcp_info.tcpi_last_data_recv);
        fprintf(stderr, "  last_ack_recv: %lu\n", (unsigned long) tcp_info.tcpi_last_ack_recv);
        fprintf(stderr, "           pmtu: %lu\n", (unsigned long) tcp_info.tcpi_pmtu);
        fprintf(stderr, "   rcv_ssthresh: %lu\n", (unsigned long) tcp_info.tcpi_rcv_ssthresh);
        fprintf(stderr, "            rtt: %lu\n", (unsigned long) tcp_info.tcpi_rtt);
        fprintf(stderr, "         rttvar: %lu\n", (unsigned long) tcp_info.tcpi_rttvar);
        fprintf(stderr, "   snd_ssthresh: %lu\n", (unsigned long) tcp_info.tcpi_snd_ssthresh);
        fprintf(stderr, "       snd_cwnd: %lu\n", (unsigned long) tcp_info.tcpi_snd_cwnd);
        fprintf(stderr, "         advmss: %lu\n", (unsigned long) tcp_info.tcpi_advmss);
        fprintf(stderr, "     reordering: %lu\n", (unsigned long) tcp_info.tcpi_reordering);
        fprintf(stderr, "        rcv_rtt: %lu\n", (unsigned long) tcp_info.tcpi_rcv_rtt);
        fprintf(stderr, "      rcv_space: %lu\n", (unsigned long) tcp_info.tcpi_rcv_space);
        fprintf(stderr, "  total_retrans: %lu\n", (unsigned long) tcp_info.tcpi_total_retrans);
        fprintf(stderr, "    pacing_rate: %lu\n", (unsigned long) tcp_info.tcpi_pacing_rate);
        fprintf(stderr, "max_pacing_rate: %lu\n", (unsigned long) tcp_info.tcpi_max_pacing_rate);
        fprintf(stderr, "    bytes_acked: %lu\n", (unsigned long) tcp_info.tcpi_bytes_acked);
        fprintf(stderr, " bytes_received: %lu\n", (unsigned long) tcp_info.tcpi_bytes_received);
        fprintf(stderr, "       segs_out: %lu\n", (unsigned long) tcp_info.tcpi_segs_out);
        fprintf(stderr, "        segs_in: %lu\n", (unsigned long) tcp_info.tcpi_segs_in);
        fprintf(stderr, "  notsent_bytes: %lu\n", (unsigned long) tcp_info.tcpi_notsent_bytes);
        fprintf(stderr, "        min_rtt: %lu\n", (unsigned long) tcp_info.tcpi_min_rtt);
        fprintf(stderr, "   data_segs_in: %lu\n", (unsigned long) tcp_info.tcpi_data_segs_in);
        fprintf(stderr, "  data_segs_out: %lu\n", (unsigned long) tcp_info.tcpi_data_segs_out);
    } 
    else 
    {
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
     * poll is never restarted if interrupted, regardless of SA_RESTART.
     * If the server side is polling, upon receiving SIGUSR it will will return
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
                fprintf(stderr,"Could not install SIGUSR1 signal\n");
            else
                fprintf(stderr,"Signal handler installed correctly\n");
        }
    }
    
    int (*socket_libc)(int, int, int);
    socket_libc = (int(*)(int, int, int))dlsym(RTLD_NEXT, "socket");
    int fd = (*socket_libc)(domain, type, protocol);
    
    /* Consider only SOCK_STREAM sockets */
    if(type != SOCK_STREAM)
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
     * on a socket which has not been initialized or on a socket != SOCK_STREAM,
     * which should not happen anyway. Do nothing in this case */

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

