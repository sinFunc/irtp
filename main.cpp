#include <iostream>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <string>

#include "ORtpSession.h"
#include "JRtpSession.h"



bool stopFlag=false;
void signalHandler(int signum){
    stopFlag=true;
}


int rcvCb(const uint8_t* buf,int len,int marker,void* user)
{
    iRtp::RtpSessionMpl* p=static_cast<iRtp::RtpSessionMpl*>(user);

    std::cout<<LOG_FIXED_HEADER()<<"seq="<<p->GetRtpHeaderData().seq<<";ts="<<p->GetRtpHeaderData().ts<<":the len of receiving payload data="<<len<<std::endl;
    return len;
}

int rtpRcvPayloadCb(const uint8_t* buf,int len,int marker,void* user)
{
    iRtp::RtpSessionMpl* p=static_cast<iRtp::RtpSessionMpl*>(user);

    std::cout<<LOG_FIXED_HEADER()<<"seq="<<p->GetRtpHeaderData().seq<<";ts="<<p->GetRtpHeaderData().ts<<":the len of receiving payload data="<<len<<std::endl;
    return len;
}
int rtpRcvPacketCb(const uint8_t* buf,int len,int marker,void* user)
{
    iRtp::RtpSessionMpl* p=static_cast<iRtp::RtpSessionMpl*>(user);

    std::cout<<LOG_FIXED_HEADER()<<"seq="<<p->GetRtpHeaderData().seq<<";ts="<<p->GetRtpHeaderData().ts<<":the len of receiving packet data="<<len<<std::endl;
    return len;
}

void rtcpAppRcvCb(void* rtcpPacket,void* user)
{
    iRtp::RtpSessionMpl* p=static_cast<iRtp::RtpSessionMpl*>(user);

    iRtp::RtcpPacket* rp=static_cast<iRtp::RtcpPacket*>(rtcpPacket);

    std::cout<<LOG_FIXED_HEADER()<<"name="<<p->GetAppName(rp)<<";subType="<<p->GetAppSubType(rp)<<std::endl;

}
void RtcpSdesItemRcvCb(void* rtcpPacket,void* user)
{
    iRtp::RtpSessionMpl* p=static_cast<iRtp::RtpSessionMpl*>(user);

    iRtp::RtcpPacket* rp=static_cast<iRtp::RtcpPacket*>(rtcpPacket);

    std::cout<<LOG_FIXED_HEADER()<<"len="<<p->GetSdesItemDataLen(rp)<<std::endl;

}
void RtcpSdesPrivateItemRcvCb(void* rtcpPacket,void* user)
{
    iRtp::RtpSessionMpl* p=static_cast<iRtp::RtpSessionMpl*>(user);

    iRtp::RtcpPacket* rp=static_cast<iRtp::RtcpPacket*>(rtcpPacket);

    std::cout<<LOG_FIXED_HEADER()<<"len="<<p->GetSdesPrivateValueDataLen(rp)<<std::endl;

}
void RtcpByeRcvCb(void* rtcpPacket,void* user)
{
    iRtp::RtpSessionMpl* p=static_cast<iRtp::RtpSessionMpl*>(user);

    iRtp::RtcpPacket* rp=static_cast<iRtp::RtcpPacket*>(rtcpPacket);

    std::cout<<LOG_FIXED_HEADER()<<"bye reason length="<<p->GetByeReasonDataLen(rp)<<std::endl;

}
void RtcpUnKnownRcvCb(void* rtcpPacket,void* user)
{
    iRtp::RtpSessionMpl* p=static_cast<iRtp::RtpSessionMpl*>(user);

    iRtp::RtcpPacket* rp=static_cast<iRtp::RtcpPacket*>(rtcpPacket);

    std::cout<<LOG_FIXED_HEADER()<<"len="<<p->GetUnKnownRtcpPacketDataLen(rp)<<std::endl;

}
void RtcpRRRcvCb(void* rtcpPacket,void* user)
{
    iRtp::RtpSessionMpl* p=static_cast<iRtp::RtpSessionMpl*>(user);

    iRtp::RtcpPacket* rp=static_cast<iRtp::RtcpPacket*>(rtcpPacket);

    std::cout<<LOG_FIXED_HEADER()<<"lost packet="<<p->GetRRLostPacketNumber(rp)<<std::endl;

}
void RtcpSRRcvCb(void* rtcpPacket,void* user)
{
    iRtp::RtpSessionMpl* p=static_cast<iRtp::RtpSessionMpl*>(user);

    iRtp::RtcpPacket* rp=static_cast<iRtp::RtcpPacket*>(rtcpPacket);

    std::cout<<LOG_FIXED_HEADER()<<"sender packet count="<<p->GetSRSenderPacketCount(rp)<<std::endl;

}


//test ortp lib and as a example
int testORtp(const std::string& lIp="",int lPort=-1,const std::string& rIp="",int rPort=-1)
{
    std::cout<<"Start ortp test"<<std::endl;

    iRtp::RtpSessionMpl* pSession=new iRtp::ORtpSession;
    assert(pSession);

    iRtp::RtpSessionInitData initData(lIp,rIp,lPort,rPort,96,90000);
    if(!pSession->Init(&initData)){
        std::cout<<LOG_FIXED_HEADER()<<" Try to init rtpSession but fail"<<std::endl;
        delete pSession;
        return -1;
    }

    int repeat=2;
    uint8_t buf[1024*1024]={0};
//    uint8_t buf[]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x20};
    while (repeat--){
        int len=pSession->SendData(buf,sizeof(buf)-repeat,0);
    }

    const int rcvLen=1400;
    uint8_t rcvBuf[rcvLen];
    while(!stopFlag){
        pSession->RcvPayloadData(rcvBuf,rcvLen,rcvCb,pSession);
        sleep(1);
    }

    pSession->Stop();
    delete pSession;

    return 0;
}


int testJRtp(const std::string& lIp="",int lPort=-1,const std::string& rIp="",int rPort=-1)
{
    std::cout<<"Start jrtp test"<<std::endl;

    iRtp::RtpSessionMpl* pSession=new iRtp::JRtpSession;
    assert(pSession);

    iRtp::RtpSessionInitData initData(lIp,rIp,lPort,rPort,96,90000);
    if(!pSession->Init(&initData)){
        std::cout<<LOG_FIXED_HEADER()<<" Try to init rtpSession but fail"<<std::endl;
        delete pSession;
        return -1;
    }

    pSession->RegisterRtcpRcvCb(iRtp::RtcpRcvCbData::APP_PACKET,rtcpAppRcvCb,pSession);
    pSession->RegisterRtcpRcvCb(iRtp::RtcpRcvCbData::SDES_ITEM,RtcpSdesItemRcvCb,pSession);
    pSession->RegisterRtcpRcvCb(iRtp::RtcpRcvCbData::SDES_PRIVATE_ITEM,RtcpSdesPrivateItemRcvCb,pSession);
    pSession->RegisterRtcpRcvCb(iRtp::RtcpRcvCbData::BYE_PACKET,RtcpByeRcvCb,pSession);
    pSession->RegisterRtcpRcvCb(iRtp::RtcpRcvCbData::RECEIVER_REPORT,RtcpRRRcvCb,pSession);
    pSession->RegisterRtcpRcvCb(iRtp::RtcpRcvCbData::SENDER_REPORT,RtcpSRRcvCb,pSession);

    pSession->RegisterRtpRcvCb(iRtp::RtpRcvCbData::ONLY_PAYLOAD,rtpRcvPayloadCb,pSession);
    pSession->RegisterRtpRcvCb(iRtp::RtpRcvCbData::WHOLE_PACKET,rtpRcvPacketCb,pSession);


    pSession->Loop();

    int repeat=30;
    uint8_t buf[100]={0};
//    uint8_t buf[]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x20};
    while (repeat--){
        int len=pSession->SendData(buf,sizeof(buf)-repeat,repeat%3);
    }

    uint8_t name[4]={'i','a','m','?'};
    pSession->SendRtcpAppData(1,name,buf,32);

//    const int rcvLen=1400;
//    uint8_t rcvBuf[rcvLen];
//    while (!stopFlag){
////        pSession->RcvData(rcvBuf,rcvLen,rcvCb,nullptr);
//        pSession->RcvPayloadData(rcvBuf,rcvLen,rcvCb,pSession);
//        sleep(1);
//    }

    pause(); //block main thread


    pSession->Stop();
    delete pSession;

    return 0;
}




int main(int agrc,char* agrv[])
{

    signal(SIGINT,signalHandler);
    signal(SIGTERM,signalHandler);
    signal(SIGQUIT,signalHandler);
    signal(SIGKILL,signalHandler);

    //default a param(whole path for executive)
    if(agrc<=1)  return testJRtp();

    std::string lip;
    std::string rip;
    int lport=-1;
    int rport=-1;

    int option=0;

    for(int i=1; i<agrc; i++){
        char* arg=agrv[i];
        //std::cout<<"arg="<<arg<<std::endl;

        std::string full(arg);
        int pos=full.find('=');
        if(pos<0){
            std::cout<<"the arg="<<arg<<" is invalid"<<std::endl;
            continue;
        }
        std::string key=full.substr(0,pos);
        std::string value=full.substr(pos+1,-1);

        if(key=="localip"){
            lip=value;
        }else if(key=="localport"){
            lport= atoi(value.data());
        }else if(key=="remoteip"){
            rip=value;
        }else if(key=="remoteport"){
            rport= atoi(value.data());
        }else if(key=="option"){
            option= atoi(value.data());
        }else{
            std::cout<<"unknown key="<<arg<<std::endl;
            return -1;
        }

    }

    int ret= option==0 ? testORtp(lip,lport,rip,rport) : testJRtp(lip,lport,rip,rport);

    sleep(1);
    return ret;
}
