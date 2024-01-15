//
// Created by sean on 2024/1/11.
//

#ifndef IRTP_RTCPPACKET_H
#define IRTP_RTCPPACKET_H
#include "ICommon.h"


namespace iRtp{

enum RtcpPackageType{
     RTCP_PACKET_RR=0,
     RTCP_PACKET_SR,
     RTCP_PACKET_APP,
     RTCP_PACKET_BYE,
     RTCP_PACKET_SDES,
     RTCP_PACKET_ORIGIN,
     RTCP_PACKET_SIZE
};



struct RtcpPacket{
    RtcpPacket(RtcpPackageType t=RTCP_PACKET_ORIGIN):type(t){}
    uint8_t* data;
    int dataLen;
    const RtcpPackageType type;
};

struct RtcpAppPacket:public RtcpPacket{
    RtcpAppPacket(): RtcpPacket(RTCP_PACKET_APP){}
    uint8_t* appData;
    int appDataLen;
    uint8_t* name;
    uint32_t ssrc;
    uint8_t subType;
};





}//namespace iRtp
#endif //IRTP_RTCPPACKET_H
