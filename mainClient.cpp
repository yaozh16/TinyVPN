//
// Created by yaozh16 on 19-5-6.
//

#include <iostream>
#include "ClientBackend.h"
class BasicNotifier:public DisconnectNotifier{
public:
    ClientBackend* backend;
    void  onDisconnect(void* arg){
        printf("disconnect:%d\n",*(int*)arg);
        backend->disconnect();
    }
};



int process(int connfd){
    printf("on connected...pid:%d\n",getpid());
    BasicNotifier notifier;
    notifier.backend= new ClientBackend(&notifier);
    notifier.backend->reset();
    //if(0>notifier.backend->connect2Server("2402:f000:4:72:808::6b04","5678")){
    if(0>notifier.backend->connect2Server("fe80::659c:fd0b:fd7:ee58","5678")){
        exit(0);
    }
    notifier.backend->setVPNFd(connfd);
    notifier.backend->startLoop();
    pause();
    return 0;
}

int openListener(){
    int listenfd, connfd;
    pid_t childpid;
    socklen_t clilen;
    struct sockaddr_in cliaddr, servaddr;
    listenfd = socket (AF_INET, SOCK_STREAM,0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl (INADDR_ANY);
    servaddr.sin_port = htons (1080);
    if(-1==bind(listenfd, (sockaddr *) &servaddr, sizeof(servaddr))){
        perror("bind\n");
        exit(0);
    }
    if(-1==listen(listenfd, 1)){
        perror("listen\n");
        exit(0);
    }
    for ( ; ; ) {
        clilen = sizeof(cliaddr);
        printf("listen...\n");
        connfd = accept(listenfd, (sockaddr *) &cliaddr, &clilen);
        if ( (childpid = fork()) == 0) { /* child process */
            close(listenfd); /* close listening socket */
            process(connfd); /* process the request */
            exit (0);
        }
        close(connfd); /* parent closes connected socket */
    }
}



int main() {
    //openListener();
    process(-1);
}