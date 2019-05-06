//
// Created by yaozh16 on 19-5-6.
//

#include "ClientBackend.h"


static void printAddrInfo(addrinfo* aip){
    char   abuf[INET6_ADDRSTRLEN];
    printf("\nhost:%s\n",aip->ai_canonname?aip->ai_canonname:"-");
    if(aip->ai_family==AF_INET) {
        struct sockaddr_in *snip=(struct sockaddr_in *)aip->ai_addr;
        const char* addr=inet_ntop(AF_INET,&snip->sin_addr,abuf,INET_ADDRSTRLEN);
        printf("\taddress\t\t:%s\n",addr?addr:"unknown");
        printf("\tport   \t\t:%d",ntohs(snip->sin_port));
    }else if(aip->ai_family==AF_INET6){
        struct sockaddr_in6 *snip=(struct sockaddr_in6 *)aip->ai_addr;
        const char* addr=inet_ntop(AF_INET6,&snip->sin6_addr,abuf,INET6_ADDRSTRLEN);
        printf("\taddress\t\t:%s\n",addr?addr:"unknown");
        printf("\tport   \t\t:%d",ntohs(snip->sin6_port));
    }
    printf("\n\tflags\t\t:");
    if(aip->ai_flags==0)
        printf("zero flag");
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


    printf("\tprotocol\t:");
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
    printf("\ttype\t\t:");
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
    printf("\tfamily\t\t:");
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
int Write(int fd,void* buff,int size){
    if(fd<0) return -1;
    while(1) {
        if (size != write(fd, buff, size)) {
            if (errno == EINTR) {
                continue;
            }
            perror("write failed\n");
            return -1;
        } else {
            return 0;
        }
    }
}
int Recv(int fd, void* buff,int maxsize){
    if(fd<0) {
        printf("fd not valid!\n");
        return -1;
    }
    do {
        int n = (int) recv(fd, buff, maxsize, 0);
        if (n <= 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recv");
            return n;
        }
        return n;
    }while (1);
}
int ClientBackend::Write2Server(Msg* msg){
    return Write(v6fd,msg,msg->length);
}

ClientBackend::ClientBackend(void *(*onDisconnect) (void *)){
    reset();
    this->onDisconnect=onDisconnect;
}

void ClientBackend::reset(){
    pthread_cancel(keepalive_t);
    pthread_cancel(client2server_t);
    pthread_cancel(server2client_t);
    v6fd=-1;
    vpnfd=-1;
    memset((void*)&statistics,1,sizeof(statistics));
    memset((void*)&allocatedAddress,1,sizeof(allocatedAddress));
    memset((void*)&v4sock,1,sizeof(v4sock));
    memset((void*)&v6sock,1,sizeof(v6sock));
    memset((void*)&msg2client,1,sizeof(msg2client));
    memset((void*)&msg2server,1,sizeof(msg2server));

}
/* 返回值: >=0成功,<0失败 */
int ClientBackend::connect2Server(const char *host, const char* service){
    int n;
    struct addrinfo hints, *res, *ressave;
    bzero(&hints, sizeof (struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ( (n = getaddrinfo (host,service, &hints, &res)) != 0) {
        printf("tcp_connect error for %s, %s: %s", host, service, gai_strerror(n));
        return -1;
    }
    ressave = res;
    do {
        printAddrInfo(res);
        v6fd = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
        if (v6fd < 0) {
            perror("v6fd<0");
            continue;
        }
        /*ignore this one */
        if (connect(v6fd, res->ai_addr, res->ai_addrlen) == 0) {
            /* success */
            break;
        } else{
            perror("connect failed\n");
        }
        close(v6fd);
        v6fd=-1;
        /* ignore this one */
    } while ( (res = res->ai_next) != NULL);
    if (res == NULL) {
        /* errno set from final connect2Server() */
        printf("tcp_connect error for %s, %s", host, service);
        return -1;
    }
    freeaddrinfo (ressave);

    /* get ipv4 address:block write,block read*/
    //sleep(1);
    printf("request ip address...\n");
    msg2server.type=TYPE_ADDRESS_REQUEST;
    msg2server.length=MSG_HEADER_SIZE;
    if(-1== Write2Server(&msg2server)){
        printf("request ipv4 address failed");
        close(v6fd);
        v6fd=-1;
        return -1;
    }

    if(0!=pthread_create(&keepalive_t,NULL,keepalive_loop,(void*)this)){
        perror("keepalive_loop thread create failed\n");
        close(v6fd);
        v6fd=-1;
        return -1;
    }
    if(0!=pthread_create(&server2client_t,NULL,server2client_loop,(void*)this)){
        perror("server2client_loop thread create failed\n");
        return -1;
    }
    return 0;
}
int ClientBackend::disconnect(){
    if(v6fd>0){
        pthread_cancel(server2client_t);
        pthread_cancel(client2server_t);
        pthread_cancel(keepalive_t);
        close(v6fd);
        v6fd=-1;
    }
}
/* 返回值：成功分配情况下：IPv4字符串;失败情况下：NULL */
const AllocatedAddress* ClientBackend::getAllocatedIPv4(){
    return &allocatedAddress;
}
/* 无返回值 */
void ClientBackend::setVPNFd(int VPNFd){
    this->vpnfd=VPNFd;
}
/* 返回值: >=0成功,<0失败*/
int ClientBackend::startLoop(){
    if(0!=pthread_create(&client2server_t,NULL,client2server_loop,(void*)this)){
        perror("client2server_loop thread create failed\n");
        return -1;
    }
}
int ClientBackend::stopLoop(){

}
ClientBackendStatistics ClientBackend::getStatistics(){
    return statistics;
}



/* private functions*/
void ClientBackend::notifyDisconnect(int arg){
    if(onDisconnect){
        onDisconnect(&arg);
    }
}

void* ClientBackend::keepalive_loop(void* clientBackend){
    auto backend=(ClientBackend*)clientBackend;
    Msg heartbeat;
    heartbeat.length=MSG_HEADER_SIZE;
    heartbeat.type=TYPE_HEARTBEAT;
    backend->server_timestamp=time(NULL);
    while(true){
        for(int i=0;i<HEARTBEAT_SEND_INTERVAL;i++){
            sleep(1);
        };
        if(time(NULL)-backend->server_timestamp>TIME_STAMP_MAX_INTERVAL){
            backend->notifyDisconnect(CLIENT_BACKEND_SERVER_FD_ERR);
            continue;
        } else{
            printf("send heartbeat\n");
            if(-1==backend->Write2Server(&heartbeat)) {
                backend->notifyDisconnect(CLIENT_BACKEND_SERVER_FD_ERR);
                continue;
            }
        }
    }
}
void* ClientBackend::client2server_loop(void* clientBackend){
    auto backend=(ClientBackend*)clientBackend;
    int n;
    backend->msg2server.type=TYPE_WORKING_REQUEST;
    while(true){
        if(backend->vpnfd<0) {
            sleep(1);
            continue;
        }
        n=Recv(backend->vpnfd,&(backend->msg2server.data),MSG_DATA_FIELD_MAX);
        if(n<=0){
            printf("recv error:%d\n",n);
            /*disconnected*/
            backend->notifyDisconnect(CLIENT_BACKEND_VPN_FD_ERR);
            continue;
        } else{
            /*修改源 IP */
            ip* iphdr=(struct ip*)backend->msg2server.data;
            iphdr->ip_src=backend->allocatedAddress.address_n;
            backend->msg2server.length=MSG_HEADER_SIZE+n;
            if(-1==backend->Write2Server(&backend->msg2server)){
                printf("send workload to server failed\n");
                backend->notifyDisconnect(CLIENT_BACKEND_SERVER_FD_ERR);
                continue;
            } else{
                backend->statistics.bytesSent+=n;

            }
        }
    }
}
void* ClientBackend::server2client_loop(void* clientBackend){
    auto backend=(ClientBackend*)clientBackend;
    int n,data_len;
    while(true){
        if(backend->v6fd<0){
            sleep(1);
            continue;
        }
        n=Recv(backend->v6fd,&(backend->msg2client),MSG_HEADER_SIZE);
        if(n<=0){
            printf("recv error:%d\n",n);
            /*disconnected*/
            backend->notifyDisconnect(CLIENT_BACKEND_SERVER_FD_ERR);
            continue;
        } else{
            printf("update timestamp\n");
            backend->server_timestamp=time(NULL);
            switch(backend->msg2client.type){
                case TYPE_HEARTBEAT:
                    printf("recv heartbeat\n");
                    break;
                case TYPE_WORKING_REPLY:
                    printf("recv workload reply");
                    data_len=Recv(backend->v6fd,backend->msg2client.data,MSG_DATA_SIZE(backend->msg2client));
                    if(data_len <MSG_DATA_SIZE(backend->msg2client)){
                        printf("recv size error\n");
                        /*disconnected*/
                        backend->notifyDisconnect(CLIENT_BACKEND_SERVER_FD_ERR);
                    } else {
                        printf("recv WORKING_REPLY\n");
                        if(MSG_DATA_SIZE(backend->msg2client)>=write(backend->vpnfd,backend->msg2client.data,MSG_DATA_SIZE(backend->msg2client))){
                            perror("vpn fd write error\n");
                            backend->notifyDisconnect(CLIENT_BACKEND_VPN_FD_ERR);
                        } else{
                            backend->statistics.bytesRecv+=MSG_DATA_SIZE(backend->msg2client);
                        }
                    }
                    break;
                case TYPE_ADDRESS_REPLY:
                    printf("recv address reply\n");
                    data_len=Recv(backend->v6fd,backend->msg2client.data,MSG_DATA_SIZE(backend->msg2client));
                    if(data_len < MSG_DATA_SIZE(backend->msg2client)){
                        printf("recv size error %d(%d)%d\n",data_len,MSG_DATA_SIZE(backend->msg2client),backend->msg2client.length-MSG_HEADER_SIZE);
                        /*disconnected*/
                        backend->notifyDisconnect(CLIENT_BACKEND_SERVER_FD_ERR);
                    } else {
                        backend->msg2client.data[MSG_DATA_SIZE(backend->msg2client)]='\0';
                        sscanf(backend->msg2client.data,"%s %s %s %s %s ",
                               backend->allocatedAddress.address,
                               backend->allocatedAddress.router,
                               backend->allocatedAddress.dns_1,
                               backend->allocatedAddress.dns_2,
                               backend->allocatedAddress.dns_3);
                        inet_aton(backend->allocatedAddress.address,&backend->allocatedAddress.address_n);
                        printf("connected as:%s\n",backend->allocatedAddress.address);
                    }
                    break;
                default:
                    printf("recv msg type error:%d\n",backend->msg2client.type);
            }
        }
    }
}