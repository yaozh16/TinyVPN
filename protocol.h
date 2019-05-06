//
// Created by yaozh16 on 19-5-6.
//

#ifndef TINYVPN_PROTOCOL_H
#define TINYVPN_PROTOCOL_H


#define MSG_DATA_FIELD_MAX  4096
#define TIME_STAMP_MAX_INTERVAL 10
#define HEARTBEAT_SEND_INTERVAL 10

struct Msg {
    int length;		    //整个结构体的字节长度
    char type;		    //类型
    char data[MSG_DATA_FIELD_MAX];	//数据段
};
#define MSG_TOTAL_SIZE(data_size)   data_size*sizeof(char)+sizeof(char)+sizeof(int)
#define MSG_HEADER_SIZE   5
#define MSG_DATA_SIZE(msg)  (msg.length-MSG_HEADER_SIZE)


#define TYPE_ADDRESS_REQUEST    100
#define TYPE_ADDRESS_REPLY      101
#define TYPE_WORKING_REQUEST    102
#define TYPE_WORKING_REPLY      103
#define TYPE_HEARTBEAT          104

#define CLIENT_BACKEND_SERVER_FD_ERR    1
#define CLIENT_BACKEND_VPN_FD_ERR       2

#endif //TINYVPN_PROTOCOL_H
