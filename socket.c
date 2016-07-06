/*
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * Author: Marco Guerri <gmarco.dev@gmail.com>
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
        fprintf(stderr, "Lost: %u, Retransmitted: %u\n",
                        tcp_info.tcpi_lost,
                        tcp_info.tcpi_total_retrans);
    } 
    else 
    {
        fprintf(stderr, "Error querying TCP_INFO\n");
    }
}

int write(int fd, const void *buf, size_t count)
{
    /* write hack to hide the fact that write might be interrupted returning
     * with EINTR. In this case, try to convince the client to try again */

    int (*write_libc)(int , const void *, size_t);
    write_libc = (int(*)(int, const void*, size_t))dlsym(RTLD_NEXT, "write");
    
    int ret = (*write_libc)(fd, buf, count);
    if(ret == -1 && errno == EINTR)
    {
        errno = EAGAIN; 
        return -1;
    }
    return ret;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    /* poll hack to make it restart when it returns with EINTR */
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
     * with EINTR and it will most likely exit. Solution might be to set a hook
     * for poll?
     */
    sigusr_action.sa_flags = SA_RESTART;
   
    struct sigaction old_action; 
    int ret = sigaction(SIGUSR1, NULL, &old_action);
    if(ret < 0) 
    {
        /* Cannot verify if the signal is installed. Forcing the installation */
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
    
    /* If socket list is null it means socket() was never called (modulo bug
     * of the library). sockfd can't be a proper socket, in this case just 
     * do nothing */
    if(list_sock != NULL)
    {
        if(list_search(list_sock, &sockfd, sizeof(int)) == NULL) 
        {
            /* Welcoming socket must be already in the list. If not, do nothing */
            fprintf(stderr, "Welcoming socket is not in the list?\n");
        }
        else
        { 
            list_sock = list_insert(list_sock, &fd, sizeof(int), list_len(list_sock)); 
        }
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

