//
// Created by yaozh16 on 19-5-6.
//

#include <iostream>
#include "ClientBackend.h"
ClientBackend* backend;
void* disconnectError(void* s){
    printf("disconnect:%d\n",*(int*)s);
    backend->disconnect();
}
int main() {
    backend=new ClientBackend(disconnectError);
    backend->reset();
    if(0>backend->connect2Server("127.0.0.1","5678")){
        printf("error");
        exit(0);
    }
    backend->startLoop();
    pause();
    return 0;
}