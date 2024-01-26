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


struct CRtpSessionInitData : public RtpSessionInitData{};

struct CRtpSessionManager{
    RtpSessionMpl* pIml{nullptr};
};

struct CRtcpPacket :public RtcpPacket{};



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

    //std::cout<<LOG_FIXED_HEADER()<<":"<<pInitData->localIp<<":"<<pInitData->localPort<<std::endl;

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
int SendDataWithTsRtpSession(CRtpSessionManager* p,const uint8_t* buf,int len,uint32_t pts,uint16_t marker)
{
    return CheckRtpSessionMgrPointer(p) ? p->pIml->SendDataWithTs(buf,len,pts,marker) : 0 ;
}
int SendDataRtpSession(CRtpSessionManager* p,const uint8_t* buf,int len,uint16_t marker)
{
    return CheckRtpSessionMgrPointer(p) ? p->pIml->SendData(buf,len,marker) : 0 ;
}

int RcvDataWithTsRtpSession(CRtpSessionManager* p,uint8_t* buf,int len,uint32_t ts,CRcvCb rcvCb,void* user)
{

   return CheckRtpSessionMgrPointer(p) ? p->pIml->RcvDataWithTs(buf,len,ts,rcvCb,user):0;
}

int RcvDataRtpSession(CRtpSessionManager* p,uint8_t* buf,int len,CRcvCb rcvCb,void* user)
{
    return CheckRtpSessionMgrPointer(p) ? p->pIml->RcvData(buf,len,rcvCb,user) : 0;
}

bool RegisterRtcpRcvCb(CRtpSessionManager* p,int type,void* cb,void* user)
{
    if(type>=RtcpRcvCbData::SIZE){
        std::cerr<<LOG_FIXED_HEADER()<<"The type is invalid."<<std::endl;
        return false;
    }

    if(!cb){
        std::cerr<<LOG_FIXED_HEADER()<<"The callback function is invalid."<<std::endl;
        return false;
    }
    RtcpRcvCb pf=(RtcpRcvCb)(cb);
    if(!pf){
        std::cerr<<LOG_FIXED_HEADER()<<"The callback function pointer is invalid."<<std::endl;
        return false;
    }

    return CheckRtpSessionMgrPointer(p) && p->pIml->RegisterRtcpRcvCb(type,pf,user);

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
        std::cerr<<LOG_FIXED_HEADER()<<":invalid function pointer."<<std::endl;
        return ;
    }

    delete pi;
}

CRtpSessionInitData* SetLocalIp(CRtpSessionInitData* p,const char* localIp){
    if(p){
        p->localIp=localIp;
    }

    return p;
}
CRtpSessionInitData* SetRemoteIp(CRtpSessionInitData* p,const char* remoteIp){
    if(p)p->remoteIp=remoteIp;
    return p;
}
CRtpSessionInitData* SetLocalPort(CRtpSessionInitData* p,int localPort){
    if(p)p->localPort=localPort;
    return p;
}
CRtpSessionInitData* SetRemotePort(CRtpSessionInitData* p,int remotePort){
    if(p)p->remotePort=remotePort;
    return p;
}
CRtpSessionInitData* SetPayloadType(CRtpSessionInitData* p,int pt){
    if(p)p->payloadType=pt;
    return p;
}
CRtpSessionInitData* SetClockRate(CRtpSessionInitData* p,int cr){
    if(p)p->clockRate=cr;
    return p;
}
CRtpSessionInitData* addPairsParams(CRtpSessionInitData* p,const char* key,const char* value){
    if(!key || !value){
        std::cerr<<LOG_FIXED_HEADER()<<"The key or value is invalid."<<std::endl;
        return p;
    }
    if(p){
        p->AddPairsParam(key,value);
    }

    return p;
}


static inline const RtpSessionMpl* checkRtpSessionMpl(void* p){
    CRtpSessionManager* pm=static_cast<CRtpSessionManager*>(p);
    if(pm==nullptr){
        std::cerr<<LOG_FIXED_HEADER()<<" invalid pointer"<<std::endl;
        return nullptr;
    }
    return pm->pIml;
}
uint32_t GetTimeStamp(void* p){
    const RtpSessionMpl* imp= checkRtpSessionMpl(p);
    return imp ? imp->GetRtpHeaderData().ts : 0;
}
uint16_t GetSequenceNumber(void* p){
    const RtpSessionMpl* imp= checkRtpSessionMpl(p);
    return imp ? imp->GetRtpHeaderData().seq : 0;
//    return ((CRtpSessionManager*)(p))->pIml->GetRtpHeaderData().seq;
}
uint32_t GetSsrc(void* p) {
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);
    return imp ? imp->GetRtpHeaderData().ssrc : 0;
//    return ((CRtpSessionManager*)(p))->pIml->GetRtpHeaderData().ssrc;
}
uint32_t* GetCsrc(void* p){
    const RtpSessionMpl* imp= checkRtpSessionMpl(p);
    return imp ? (uint32_t*)imp->GetRtpHeaderData().csrc : nullptr;
//    return (uint32_t*) ((CRtpSessionManager*)(p))->pIml->GetRtpHeaderData().csrc;
}
uint16_t GetPayloadType(void* p){
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);
    return imp ? imp->GetRtpHeaderData().pt : 0;
//    return ((CRtpSessionManager*)(p))->pIml->GetRtpHeaderData().pt;
}
bool GetMarker(void* p){
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);
    return imp ? imp->GetRtpHeaderData().marker : 0;
//    return ((CRtpSessionManager*)(p))->pIml->GetRtpHeaderData().marker;
}
uint8_t  GetVersion(void* p){
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);
    return imp ? imp->GetRtpHeaderData().version : 0;
//    return ((CRtpSessionManager*)(p))->pIml->GetRtpHeaderData().version;
}
bool GetPadding(void* p){
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);
    return imp ? imp->GetRtpHeaderData().padding : 0;
//    return ((CRtpSessionManager*)(p))->pIml->GetRtpHeaderData().padding;
}
bool GetExtension(void* p){
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);
    return imp ? imp->GetRtpHeaderData().extension : 0;
//    return ((CRtpSessionManager*)(p))->pIml->GetRtpHeaderData().extension;
}
uint8_t  GetCC(void* p){
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);
    return imp ? imp->GetRtpHeaderData().cc : 0;
//    return ((CRtpSessionManager*)(p))->pIml->GetRtpHeaderData().cc;
}



static inline RtcpPacket* checkRtcpPacketPointer(void* p){
    RtcpPacket* rp=static_cast<RtcpPacket*>(p);
    if(!rp){
        std::cerr<<LOG_FIXED_HEADER()<<"The pointer is invalid."<<std::endl;
    }

    return rp;

}
uint8_t* GetRtcpPacketData(void* p,void* rtcpPacket){
    RtcpPacket* rp= checkRtcpPacketPointer(rtcpPacket);
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);

    return (imp && rp) ? imp->GetPacketData(rp) : nullptr;
}
int GetPacketDataLength(void* p,void* rtcpPacket){
    RtcpPacket* rp= checkRtcpPacketPointer(rtcpPacket);
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);

    return (imp && rp) ? imp->GetPacketDataLength(rp) : 0;
}
uint8_t* GetAppData(void* p,void*rtcpPacket){
    RtcpPacket* rp= checkRtcpPacketPointer(rtcpPacket);
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);

    return (imp && rp) ? imp->GetAppData(rp) : nullptr;
}
int GetAppDataLength(void* p,void* rtcpPacket){
    RtcpPacket* rp= checkRtcpPacketPointer(rtcpPacket);
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);

    return (imp && rp) ? imp->GetAppDataLength(rp) : 0;
}
uint8_t* GetAppName(void* p,void* rtcpPacket){
    RtcpPacket* rp= checkRtcpPacketPointer(rtcpPacket);
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);

    return (imp && rp) ? imp->GetAppName(rp) : nullptr;
}
uint32_t GetAppSsrc(void* p,void* rtcpPacket){
    RtcpPacket* rp= checkRtcpPacketPointer(rtcpPacket);
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);

    return (imp && rp) ? imp->GetAppSsrc(rp) : 0 ;
}
uint8_t GetAppSubType(void* p,void* rtcpPacket){
    RtcpPacket* rp= checkRtcpPacketPointer(rtcpPacket);
    const RtpSessionMpl *imp = checkRtpSessionMpl(p);

    return (imp && rp) ? imp->GetAppSubType(rp) : 0 ;
}

