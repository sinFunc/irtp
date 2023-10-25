//
// Created by sean on 2023/10/23.
//

#include <assert.h>
#include "RtpSessionMpl.h"
#include "ORtpSession.h"
#include "JRtpSession.h"

extern "C" {
    #include "cgo_RtpSessionManager.h"
}

using namespace iRtp;


struct CRtpSessionInitData : public RtpSessionInitData{

};

struct CRtpSessionManager{
    RtpSessionMpl* pIml{nullptr};
};


static inline bool CheckRtpSessionMgrPointer(CRtpSessionManager* p)
{
    if(!p || !p->pIml){
        std::cout<<LOG_FIXED_HEADER()<<" invalid pointer."<<std::endl;
        return false;
    }

    return true;
}


CRtpSessionManager* CreateRtpSession(CRtpSessionType t)
{
    CRtpSessionManager* p=new CRtpSessionManager();
    assert(p);

    switch (t) {
        case CRtpSessionType::CRtpSessionType_ORTP:
            p->pIml=new ORtpSession;
            break;

        case CRtpSessionType::CRtpSessionType_JRTP:
            p->pIml=new JRtpSession;
            break;

        default:
            std::cout<<LOG_FIXED_HEADER()<<" invalid rtp session type="<<t<<std::endl;
            break;
    }//switch

    return p;

}
void DestroyRtpSession(CRtpSessionManager* p)
{
    if(!p || !p->pIml){
        std::cout<<LOG_FIXED_HEADER()<<" invalid pointer."<<std::endl;
        return;
    }

    delete p->pIml;
    p->pIml=nullptr;

    delete p;


}
bool InitRtpSession(CRtpSessionManager* p,CRtpSessionInitData* pInitData)
{
    if(!p || !p->pIml || !pInitData){
        std::cout<<LOG_FIXED_HEADER()<<" invalid pointer."<<std::endl;
        return false;
    }

    std::cout<<LOG_FIXED_HEADER()<<":"<<pInitData->localIp<<":"<<pInitData->localPort<<std::endl;

    return p->pIml->Init(pInitData);

}
bool StartRtpSession(CRtpSessionManager* p)
{
    return CheckRtpSessionMgrPointer(p) && p->pIml->Start();

}
bool StopRtpSession(CRtpSessionManager* p)
{
    return CheckRtpSessionMgrPointer(p) && p->pIml->Stop();
}
int SendDataRtpSession(CRtpSessionManager* p,const uint8_t* buf,int len,uint32_t pts,uint64_t marker)
{
//    std::cout<<LOG_FIXED_HEADER()<<std::endl;
    return CheckRtpSessionMgrPointer(p) && p->pIml->SendData(buf,len,pts,marker);
}
int RcvDataRtpSession(CRtpSessionManager* p,uint8_t* buf,int len,uint32_t ts,CRcvCb rcvCb,void* user)
{
//    RcvCb fp=(RcvCb)(rcvCb);
//   if(!fp){
//       std::cout<<LOG_FIXED_HEADER()<<":invalid function pointer."<<std::endl;
//       return -1;
//   }

   return CheckRtpSessionMgrPointer(p) && p->pIml->RcvData(buf,len,ts,rcvCb,user);

}


CRtpSessionInitData* CreateRtpSessionInitData(const char* localIp,const char* remoteIp,int localPort
        ,int remotePort,int payloadType,int clockRate)
{
    CRtpSessionInitData* pi= new CRtpSessionInitData();
    assert(pi);

    pi->localIp=localIp;
    pi->remoteIp=remoteIp;
    pi->localPort=localPort;
    pi->remotePort=remotePort;
    pi->payloadType=payloadType;
    pi->clockRate=clockRate;

    return pi;

}
void DestroyRtpSessionInitData(CRtpSessionInitData* pi)
{
    if(!pi){
        std::cout<<LOG_FIXED_HEADER()<<":invalid function pointer."<<std::endl;
        return ;
    }

    delete pi;



}
