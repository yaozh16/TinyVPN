//
// Created by yaozh16 on 19-4-25.
//
#include "TunManager.h"
#define WORKING_PROCESS_COUNT 4


int main(){
    TunManager::initMutex();
    TunManager::initListenEpollFd(LISTENER_MAX);
    //TunManager::initServerFdPool(AF_UNSPEC,"5678",LISTENQ);
    TunManager::initServerFdPool(AF_INET6,"5678",LISTENQ);
    system("iptables -F");
    system("iptables -t nat -F");
    system("echo \"1\" > /proc/sys/net/ipv4/ip_forward");
    system("iptables -A FORWARD -j ACCEPT");
    system("iptables -t nat -A POSTROUTING  -s 10.0.0.0/8 -j MASQUERADE");
    //system("iptables -t nat -A POSTROUTING -s 10.0.0.0/8  -j MASQUERADE");
    int i;
    for(i=0;i<WORKING_PROCESS_COUNT-1;i++) {
        if(0==fork()){
            break;
        }
    }
    assert(!TunManager::existsManager());
    char addr[100];

    snprintf(addr,100,"10.0.%d.%d",i,i+3);

    TunManager* manager= TunManager::getSingleton(addr,i);
    manager->run();
}