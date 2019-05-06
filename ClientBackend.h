//
// Created by yaozh16 on 19-5-6.
//

#ifndef INC_4OVER6CLIENT_BACKEND_CLIENTBACKEND_H
#define INC_4OVER6CLIENT_BACKEND_CLIENTBACKEND_H


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
#include <netdb.h>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include "protocol.h"
#include<netinet/ip.h>
struct AllocatedAddress{
    char address[NI_MAXHOST];
    char router[NI_MAXHOST];
    char dns_1[NI_MAXHOST];
    char dns_2[NI_MAXHOST];
    char dns_3[NI_MAXHOST];
    in_addr address_n;
};
struct ClientBackendStatistics{
    unsigned long bytesSent;
    unsigned long bytesRecv;
    /*.....other statistics*/
};
class ClientBackend {
public:
    /*构造参数: 连接断开时的回调函数
     *      该回调调用的时机为：
     *          连接成功后(0==connect2Server(...))
     *          出现断开(向服务器发送或者接收数据失败)\或者VPNfd失效(读写出错)的时候
     *          如果不做处理,一次连接中,onDisconnect可能会被调用多次(读失败和写失败均可能调用一次)
     *          但是可以在onDisconnect中调用ClientBackend的disconnect等函数
     * */
    explicit ClientBackend(void *(*onDisconnect) (void *));
    /* 全部初始化 */
    void reset();
    /* 返回值: >=0成功,<0失败 */
    int connect2Server(const char *host, const char* service);
    /* 会杀死所有下属子线程并关闭v6fd */
    int disconnect();
    /* 返回值：成功分配情况下：IPv4字符串;失败情况下：NULL */
    const AllocatedAddress* getAllocatedIPv4();
    /* 无返回值 */
    void setVPNFd(int VPNFd);
    /* 返回值: >=0成功,<0失败*/
    int startLoop();
    int stopLoop();
    ClientBackendStatistics getStatistics();
private:
    sockaddr_in v4sock; //仅作信息保存之用
    sockaddr_in6 v6sock;//实际连接服务器使用

    int vpnfd;
    int v6fd;

    void *(*onDisconnect) (void *);

    ClientBackendStatistics statistics;
    AllocatedAddress allocatedAddress;

    pthread_t keepalive_t;
    pthread_t client2server_t;
    pthread_t server2client_t;
    Msg msg2server;
    Msg msg2client;

    time_t server_timestamp;

    void notifyDisconnect(int);
    int Write2Server(Msg* msg);
private:
    static void* keepalive_loop(void* clientBackend);
    static void* client2server_loop(void* clientBackend);
    static void* server2client_loop(void* clientBackend);

};


#endif //INC_4OVER6CLIENT_BACKEND_CLIENTBACKEND_H
