//
// Created by yaozh16 on 19-5-6.
//

#include <iostream>
#include "ClientBackend.h"
ClientBackend* backend;
void* onDisconnect(void *s){
    printf("disconnect:%d\n",*(int*)s);
    backend->disconnect();
}
int main() {
    backend= new ClientBackend(onDisconnect);
    backend->reset();
    if(0>backend->connect2Server("2402:f000:4:72:808::6b04","5678")){
        printf("error");
        exit(0);
    }
    backend->startLoop();
    pause();
    return 0;
}