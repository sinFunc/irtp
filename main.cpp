#include <iostream>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <string>

#include "ORtpSession.h"
#include "JRtpSession.h"


//#include "rtpsession.h"
//#include "rtpudpv4transmitter.h"
//#include "rtpsessionparams.h"
//#include "rtpipv4address.h"
//#include "rtppacket.h"
//#include "rtptimeutilities.h"


bool stopFlag=false;
void signalHandler(int signum){
    stopFlag=true;
}


int rcvCb(const uint8_t* buf,int len,int marker,void* user)
{
    std::cout<<LOG_FIXED_HEADER()<<":the len of receiving payload data="<<len<<std::endl;
    return len;
}

//test ortp lib and as a example
int testORtp(const std::string& lIp="",int lPort=-1,const std::string& rIp="",int rPort=-1)
{
    std::cout<<"Start ortp test"<<std::endl;

    iRtp::RtpSessionMpl* pSession=new iRtp::ORtpSession;
    assert(pSession);

    iRtp::RtpSessionInitData initData{lIp,rIp,lPort,rPort,96,90000};
    if(!pSession->Init(&initData) || !pSession->Start()){
        std::cout<<LOG_FIXED_HEADER()<<" Try to init rtpSession but fail"<<std::endl;
        delete pSession;
        return -1;
    }

    int repeat=9;
    uint8_t buf[]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x20};
    while (repeat--){
        int len=pSession->SendData(buf,sizeof(buf)-repeat,0);
    }

    const int rcvLen=1024;
    uint8_t rcvBuf[rcvLen];
    while(!stopFlag){
        pSession->RcvPayloadData(rcvBuf,rcvLen,rcvCb,nullptr);
        sleep(1);
    }

    pSession->Stop();
    delete pSession;

    return 0;
}


//int testJrtp(const std::string& lIp="",int lPort=-1,const std::string& rIp="",int rPort=-1)
//{
//    using namespace jrtplib;
//
//    RTPSession session;
//    RTPSessionParams sessParams;
//    RTPUDPv4TransmissionParams transParams;
//
//    sessParams.SetOwnTimestampUnit(1/90000);
////    sessParams.SetAcceptOwnPackets(true);
//
//    //bind local ip and port
//    const char* lip=lIp!="" ? lIp.data() : "127.0.0.1";
//    unsigned long localIp=ntohl(inet_addr(lip));
//    transParams.SetBindIP(localIp);
//
//    const int lport= lPort>0? lPort : 60000;
//    transParams.SetPortbase(lport);
//    int status=session.Create(sessParams,&transParams);
//    if(status<0){
//        std::cerr<<RTPGetErrorString(status)<<std::endl;
//        return -1;
//    }
//
//    const char* rip=rIp!="" ? rIp.data() : "127.0.0.1";
//    unsigned long remoteIp=ntohl(inet_addr(rip));
//    const int rport= rPort>0? rPort : 6666;
//    RTPIPv4Address addr(remoteIp,rport);
//
//    status=session.AddDestination(addr);
//    if(status<0){
//        std::cerr<<RTPGetErrorString(status)<<std::endl;
//        return -1;
//    }
//
//    session.SetDefaultMark(false);
//    session.SetDefaultPayloadType(96);
//    session.SetDefaultTimestampIncrement(3600);
//
//    int repeat=10;
//    uint8_t buf[]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09};
//    while (repeat--){
//        status=session.SendPacket(buf,10);
//        if(status<0){
//            std::cerr<<RTPGetErrorString(status)<<std::endl;
//            return -1;
//        }
//    }
//
//    while(!stopFlag){
//        session.BeginDataAccess();
//        if(session.GotoFirstSource()){
//            do{
//                RTPPacket* pkt;
//                while ((pkt=session.GetNextPacket())!=0){
//                    std::cout<<"Got packet with "
//                    << "sequence number="<<pkt->GetExtendedSequenceNumber()
//                    <<" from SSRC "<<pkt->GetSSRC()
//                    <<std::endl;
//                    session.DeletePacket(pkt);
//                }
//
//            }while(session.GotoNextSource() && !stopFlag);
//        }
//        session.EndDataAccess();
//        sleep(1);
//    }
//
//    session.BYEDestroy(0,"time is up",10);
//
//    return 0;
//}

int testJRtp(const std::string& lIp="",int lPort=-1,const std::string& rIp="",int rPort=-1)
{

    std::cout<<"Start jrtp test"<<std::endl;

    iRtp::RtpSessionMpl* pSession=new iRtp::JRtpSession;
    assert(pSession);

    iRtp::RtpSessionInitData initData{lIp,rIp,lPort,rPort,96,90000};
    if(!pSession->Init(&initData) || !pSession->Start()){
        std::cout<<LOG_FIXED_HEADER()<<" Try to init rtpSession but fail"<<std::endl;
        delete pSession;
        return -1;
    }

    int repeat=9;
    uint8_t buf[]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x20};
    while (repeat--){
        int len=pSession->SendData(buf,sizeof(buf)-repeat,0);
    }

    const int rcvLen=1024;
    uint8_t rcvBuf[rcvLen];
    while (!stopFlag){
//        pSession->RcvData(rcvBuf,rcvLen,rcvCb,nullptr);
        pSession->RcvPayloadData(rcvBuf,rcvLen,rcvCb,nullptr);
        sleep(1);
    }

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
    if(agrc<=1)  return testORtp();

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

    return option==0 ? testORtp(lip,lport,rip,rport) : testJRtp(lip,lport,rip,rport);


}
