//
// Created by yaozh16 on 19-5-6.
//

#ifndef TINYVPN_TUNMANAGER_H
#define TINYVPN_TUNMANAGER_H

#include <thread>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>
#include  <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <string>
#include <vector>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include "protocol.h"
#include <linux/ip.h>
#include <unistd.h>
#define LISTENER_MAX      5
#define EPOLL_EVENT_MAX  100
#define EVENT_LIST_MAX   100
#define LISTENQ          10

typedef int (*PFCALLBACL)(struct epoll_event *);


typedef struct EPOLL_DATA_S
{
    int epoll_Fd;
    int event_Fd;
    PFCALLBACL pfCallBack;
}Epoll_Data_S;



/*负责一个虚拟设备的管理以及在此设备上的通信*/
class TunManager{
private:
    static int serverFdPool[LISTENER_MAX];
    static int serverFdPoolSize;
    static void printAddrInfo(addrinfo* aip){
        char   abuf[INET6_ADDRSTRLEN];
        printf("\nhost:%s\n",aip->ai_canonname?aip->ai_canonname:"-");
        if(aip->ai_family==AF_INET) {
            struct sockaddr_in *snip=(struct sockaddr_in *)aip->ai_addr;
            const char* addr=inet_ntop(AF_INET,&snip->sin_addr,abuf,INET_ADDRSTRLEN);
            printf("\taddress:%s\n",addr?addr:"unknown");
            printf("\tport   :%d",ntohs(snip->sin_port));
        }else if(aip->ai_family==AF_INET6){
            struct sockaddr_in6 *snip=(struct sockaddr_in6 *)aip->ai_addr;
            const char* addr=inet_ntop(AF_INET6,&snip->sin6_addr,abuf,INET6_ADDRSTRLEN);
            printf("\taddress:%s\n",addr?addr:"unknown");
            printf("\tport   :%d",ntohs(snip->sin6_port));
        }
        printf("\n\tflags:");
        if(aip->ai_flags==0)
            printf("0");
        else if(aip->ai_flags& AI_PASSIVE)
            printf("passive");
        else if(aip->ai_flags&AI_CANONNAME)
            printf("cannoname");
        else  if(aip->ai_flags&AI_NUMERICHOST)
            printf("numhost");
#if defined (AI_V4MAPPED)
        else  if(aip->ai_flags&AI_V4MAPPED)
            printf("v4mampped");
#endif
#if defined (AI_ALL)
        else  if(aip->ai_flags&AI_ALL)
            printf("all");
#endif
        printf("\n");


        printf("\tprotocol:");
        switch(aip->ai_protocol)
        {
            case 0:
                printf("default");
                break;
            case IPPROTO_TCP:  //不固定的。长度不可靠的报文
                printf("tcp");
                break;
            case IPPROTO_UDP:
                printf("udp");//长度固顶有序，面向连接的报文
                break;
            case IPPROTO_RAW:
                printf("raw");//面向底层ip协议的套接字
                break;
            default:
                printf("unknown (%d)",aip->ai_protocol);

        }

        printf("\n");
        printf("\ttype:");
        switch(aip->ai_socktype)
        {
            case SOCK_STREAM:
                printf("stream");
                break;
            case SOCK_DGRAM:  //不固定的。长度不可靠的报文
                printf("datagram");
                break;
            case SOCK_SEQPACKET:
                printf("seqpacket");//长度固顶有序，面向连接的报文
                break;
            case SOCK_RAW:
                printf("raw");//面向底层ip协议的套接字
                break;
            default:
                printf("unknown (%d)",aip->ai_socktype);
        }

        printf("\n");
        printf("\tfamily:");
        switch(aip->ai_family)
        {
            case AF_INET:
                printf("inet");
                break;
            case AF_INET6:
                printf("inet6");
                break;
            case AF_UNIX:
                printf("unix");
                break;
            case AF_UNSPEC:
                printf("unspecified");
                break;
            default:
                printf("unknown");
                printf("\n");
        }
        printf("\n");
    }
    static int makeSocketNonBlocking(int fd){
        int flags;
        if ((flags = fcntl (fd, F_GETFL, 0)) == -1) {
            perror ("fcntl");
            return -1;
        }
        flags |= O_NONBLOCK;
        if (-1==fcntl (fd, F_SETFL, flags)) {
            perror ("fcntl");
            return -1;
        }
        return 0;
    }
    static int listenEpollFd;
    static int recvEpollFd; //虽然是开始就分配了但是各个进程这个值不同
    static pthread_mutex_t* mutex;
    static epoll_event* events;
public:
    static int initMutex(){
        pthread_mutexattr_t attr;
        int ret;

        //设置互斥量为进程间共享
        mutex=(pthread_mutex_t*)mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANON, -1, 0);
        if( MAP_FAILED==mutex) {
            perror("mutex mmap failed");
            return -1;
        }

        //设置attr的属性
        pthread_mutexattr_init(&attr);
        ret = pthread_mutexattr_setpshared(&attr,PTHREAD_PROCESS_SHARED);
        if(ret != 0) {
            fprintf(stderr, "mutex set shared failed");
            return -1;
        }
        pthread_mutex_init(mutex, &attr);

    }
    static int initListenEpollFd(int event_max=EPOLL_EVENT_MAX){
        listenEpollFd = epoll_create(event_max);
        if (-1 == listenEpollFd) {
            printf("epoll create failed\r\n");
            return -1;
        }
        return listenEpollFd;
    }
    static int initServerFdPool(int family,const char* service,int listenq){
        assert(serverFdPoolSize==0);
        printf("initServerFdPool\n");
        addrinfo hints;
        addrinfo *res, *ressave;
        const int on=1;
        int listenfd;

        memset(&hints, 0, sizeof(addrinfo));
        hints.ai_family = family;    /* Allow IPv4  and IPv6*/
        hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
        hints.ai_protocol = 0;          /* Any protocol */
        hints.ai_socktype = SOCK_STREAM;

        if (getaddrinfo (NULL, service, &hints, &res) != 0){
            perror("get addr info failed");
            exit(0);
        }
        ressave = res;
        do {
            printAddrInfo(res);
            listenfd =socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (listenfd < 0)
                continue;
            /* error, try next one */
            setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));

            if (bind(listenfd, res->ai_addr, res->ai_addrlen) == 0){
                /* success */
                listen(listenfd, listenq);
                makeSocketNonBlocking(listenfd);
                if(serverFdPoolSize<LISTENER_MAX-1){
                    serverFdPool[serverFdPoolSize++]=listenfd;
                } else{
                    printf("server socket pool full\n");
                    close(listenfd);
                }
            }else {
                /* bind error, close and try next one */
                close(listenfd);
            }
        } while ( (res = res->ai_next) != NULL);
        /* errno from final socket () or bind () */
        freeaddrinfo (ressave);
        for(int i=0;i<serverFdPoolSize;i++) {
            add_event_epoll(listenEpollFd, serverFdPool[i], proc_accept);
        }
    }
    /* 将事件加到epoll */
    static int add_event_epoll(int iEpoll_Fd, int iEvent_Fd, PFCALLBACL pfCallBack) {
        int                  op = EPOLL_CTL_ADD;
        struct epoll_event   ee;
        Epoll_Data_S *data;

        data = (Epoll_Data_S*)malloc(sizeof(Epoll_Data_S));
        if (NULL == data) {
            printf("malloc error");
            return -1;
        }

        /* 设置私有数据 */
        data->epoll_Fd = iEpoll_Fd;
        data->event_Fd = iEvent_Fd;
        data->pfCallBack = pfCallBack;

        ee.events = EPOLLIN |  EPOLLHUP;
        ee.data.ptr = (void *)data;

        if (epoll_ctl(iEpoll_Fd, op, iEvent_Fd, &ee) == -1){
            printf("epoll_ctl(%d, %d) failed", op, iEvent_Fd);
            perror("epoll");
            return -1;
        }
    }
    /* 从epoll删除事件 */
    static void del_event_epoll(int iEpoll_Fd, int iEvent_Fd){
        int op = EPOLL_CTL_DEL;

        if (epoll_ctl(iEpoll_Fd, op, iEvent_Fd, NULL) == -1)
        {
            printf("epoll_ctl(%d, %d) failed", op, iEvent_Fd);
        }

        return;
    }
    /* 处理Receive事件 */
    static int proc_receive(struct epoll_event *pstEvent) {
        Epoll_Data_S *data = (Epoll_Data_S *)(pstEvent->data.ptr);
        int epoll_Fd = data->epoll_Fd;
        int event_Fd = data->event_Fd;
        if (pstEvent->events & EPOLLHUP){
            del_event_epoll(epoll_Fd, event_Fd);
            close(event_Fd);
            free(data);
            manager->occupied=false;
        }else if (pstEvent->events & EPOLLIN){
            //data in
            //read from ievent fd
            if(event_Fd==manager->clientfd){
                if(!manager->occupied || 0>manager->procCliMsg()){
                    del_event_epoll(epoll_Fd, event_Fd);
                    close(event_Fd);
                    free(data);
                    manager->occupied=false;
                    printf("disconnected[%s]\n",inet_ntoa(manager->tunAddr));
                }
            }else if(event_Fd==manager->tunfd && manager->occupied){
                manager->procTunMsg();
            }
        }else if(pstEvent->events & EPOLLERR){
            del_event_epoll(epoll_Fd, event_Fd);
            close(event_Fd);
            free(data);
            manager->occupied=false;
            printf("disconnected[%s]\n",inet_ntoa(manager->tunAddr));
        }
        return 0;
    }
    /* 处理Accept事件 */
    static int proc_accept(struct epoll_event *pstEvent) {
        auto data = (Epoll_Data_S *)(pstEvent->data.ptr);
        int iEpoll_Fd = data->epoll_Fd;
        int iEvent_Fd = data->event_Fd;

        if (pthread_mutex_trylock(mutex)==0) {
            printf("accept\n");
            sockaddr_in conn;
            int nAddrlen = sizeof(conn);
            if(-1 != (manager->clientfd = accept(iEvent_Fd, (sockaddr*)&conn,(socklen_t*) &nAddrlen))) {
                char tmp[12];
                printf("%s:%d connected",inet_ntoa(conn.sin_addr),conn.sin_port);
                printf("[mapped to %s]\n",inet_ntoa(getSingleton(NULL,0)->tunAddr));
                makeSocketNonBlocking(manager->clientfd);
                //设置超时时间
                struct timeval timeout;
                timeout.tv_sec = 5;
                timeout.tv_usec = 0;
                setsockopt(manager->clientfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                add_event_epoll(recvEpollFd, manager->clientfd, proc_receive);
                manager->occupied= true;
                manager->timestamp_send=manager->timestamp_send=time(NULL);
            } else{
                perror("accept error!\n");

            }
            pthread_mutex_unlock(mutex);
        }
        return 0;
    }
    static void clearAll(){
        for(int i=0;i<LISTENER_MAX;i++) close(serverFdPool[i]);
        close(listenEpollFd);
    }



    static void proc_epoll(int epollFd, int timeout) {
        int n;
        int i;

        n = epoll_wait(epollFd, events, EVENT_LIST_MAX, timeout);
        for (i = 0; i < n; i++) {
            Epoll_Data_S *data = (Epoll_Data_S *)(events[i].data.ptr);
            data->pfCallBack(&(events[i]));
        }
    }
private:
    bool occupied;
    in_addr tunAddr;
    int index;
    int tunfd;
    int clientfd;
    time_t timestamp_recv;
    time_t timestamp_send;
    Msg msg2cli;
    Msg msg2tun;
    int allocTun(int devIndex, in_addr virtualAddress) {
        struct ifreq ifr = {0};
        char buffer[256];
        /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
         *        IFF_TAP   - TAP device
         *        IFF_NO_PI - Do not provide packet information
         */
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        snprintf(ifr.ifr_name,IF_NAMESIZE,"TinyVpn%d",devIndex);
        if((tunfd= open("/dev/net/tun", O_RDWR)) < 0) {
            perror("Cannot open TUN dev");
            return -1;
        }
        if (ioctl(tunfd, TUNSETIFF, (void *)&ifr) < 0) {
            perror("Cannot initialize TUN device");
            return -1;
        }
        sprintf(buffer,"ip link set dev %s up", ifr.ifr_name);
        system(buffer);
        sprintf(buffer,"ip link set dev %s mtu %u", ifr.ifr_name, 1500 - MSG_HEADER_SIZE);
        system(buffer);
        sprintf(buffer,"ip a add %s/32 dev %s",inet_ntoa(virtualAddress), ifr.ifr_name);
        system(buffer);
        return tunfd;
    }
    int procTunMsg(){
        uint32_t n=recv(tunfd,msg2cli.data,MSG_DATA_FIELD_MAX,0)+MSG_HEADER_SIZE;
        iphdr *hdr = (struct iphdr *)msg2cli.data;
        if(hdr->version==4) {
            printf("on tun data\n");
            if (hdr->daddr == tunAddr.s_addr) {
                msg2cli.type = TYPE_WORKING_REPLY;
                msg2cli.length = n;
                return write(clientfd, &msg2cli, msg2cli.length);
            }
        } else{
            //printf("ignore other version packet\n");
        }
        return 0;
    }
    int procCliMsg(){
        ssize_t n=recv(clientfd,&msg2tun,MSG_HEADER_SIZE,0);
        if(n<=0){ return -1; }
        timestamp_recv=time(NULL);
        switch (msg2tun.type){
            case TYPE_WORKING_REQUEST:
                printf("send request\n");
                n=recv(clientfd,msg2tun.data,MSG_DATA_SIZE(msg2tun),0);
                if(n==msg2tun.length){
                    iphdr *hdr = (struct iphdr *)msg2tun.data;
                    if(hdr->version==4){
                        hdr->saddr=tunAddr.s_addr;
                    } else{
                        printf("cannot process other version packet\n");
                    }
                    write(tunfd,msg2tun.data,MSG_DATA_SIZE(msg2tun));
                    return 0;
                } else{
                    return -1;
                }
                break;
            case TYPE_HEARTBEAT:
                printf("recv heartbeat\n");
                return 0;
            case TYPE_ADDRESS_REQUEST:
                printf("request address\n");
                msg2tun.type=TYPE_ADDRESS_REPLY;
                snprintf(msg2tun.data,MSG_DATA_FIELD_MAX,"%s %s %s %s %s ",
                         inet_ntoa(tunAddr),
                         inet_ntoa(tunAddr),
                         inet_ntoa(tunAddr),
                         inet_ntoa(tunAddr),
                         inet_ntoa(tunAddr));
                msg2tun.length=strlen(msg2tun.data)+MSG_HEADER_SIZE;
                return write(clientfd,&msg2tun,msg2tun.length);
        }
        return 0;
    }
public:
    void reset(){
        close(tunfd);
        close(clientfd);
        memset(&tunAddr,0,sizeof(tunAddr));
        tunfd=-1;
        occupied= false;
        clientfd=-1;
    }
    static bool existsManager(){ return manager!=NULL;}
    static TunManager* getSingleton(char* addr,int index){
        if(manager==NULL){
            manager=new TunManager(addr,index);
        }
        return manager;
    }
    void run(){
        while (1)
        {
            if(!occupied)
                /* 处理父epoll消息 */
                proc_epoll(listenEpollFd, 5);
            else {
                /* 处理子epoll消息 */
                proc_epoll(recvEpollFd, 5);
            }
            if(time(NULL)-timestamp_send>20 && occupied){
                printf("send heartbeat %u\n",(unsigned int)timestamp_send);
                timestamp_send=time(NULL);
                Msg tmp;
                tmp.type=TYPE_HEARTBEAT;
                tmp.length=MSG_HEADER_SIZE;
                write(clientfd,&tmp,tmp.length);
            }
        }
    }
private:
    static TunManager* manager;
    TunManager(char* addr,int index){
        occupied= false;
        clientfd=-1;
        tunfd=-1;
        timestamp_send=time(NULL);
        tunAddr={0};
        inet_aton(addr,&tunAddr);
        printf("[%d]take tun address as:%s\n",getpid(),addr);
        this->index=index;
        allocTun(this->index, this->tunAddr);
        recvEpollFd=epoll_create(EPOLL_EVENT_MAX);
        if(recvEpollFd==-1){
            exit(-1);
        }

        makeSocketNonBlocking(tunfd);
        //add_event_epoll(recvEpollFd, tunfd, proc_receive);
    }
};

int TunManager::serverFdPool[LISTENER_MAX];
int TunManager::serverFdPoolSize=0;
int TunManager::listenEpollFd=0;
int TunManager::recvEpollFd=0;
pthread_mutex_t* TunManager::mutex=NULL;
TunManager* TunManager::manager=NULL;
epoll_event* TunManager::events=new epoll_event[EVENT_LIST_MAX];

#endif //TINYVPN_TUNMANAGER_H
