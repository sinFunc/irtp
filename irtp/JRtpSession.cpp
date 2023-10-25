//
// Created by sean on 2023/10/16.
//
#include "JRtpSession.h"
#include <atomic>

using namespace jrtplib;

namespace iRtp{

JRtpSession::JRtpSession():m_nPayloadType(0),m_nCurPts(0)
{






}

JRtpSession::~JRtpSession()
{


}

bool JRtpSession::Init(const RtpSessionInitData *pInitData)
{

    unsigned long localIp=ntohl(inet_addr(pInitData->localIp.data()));
    m_transParams.SetBindIP(localIp);
    m_transParams.SetPortbase(pInitData->localPort);

    m_sessParams.SetOwnTimestampUnit(1/90000);

    int status=m_rtpSession.Create(m_sessParams,&m_transParams);
    if(status<0){
        std::cerr<<RTPGetErrorString(status)<<std::endl;
        return -1;
    }

    unsigned long remoteIp=ntohl(inet_addr(pInitData->remoteIp.data()));
    RTPIPv4Address addr(remoteIp,pInitData->remotePort);
    status=m_rtpSession.AddDestination(addr);
    if(status<0){
        std::cerr<<RTPGetErrorString(status)<<std::endl;
        return -1;
    }

    m_rtpSession.SetDefaultMark(false);
    m_rtpSession.SetDefaultPayloadType(pInitData->payloadType);

    m_nPayloadType=pInitData->payloadType;

    return true;
}

bool JRtpSession::Start()
{

    return true;
}

int JRtpSession::SendData(const uint8_t *buf, int len, uint32_t pts, uint64_t marker)
{
    //std::cout<<LOG_FIXED_HEADER()<<std::endl;

    uint32_t incPts=pts-m_nCurPts;
    m_nCurPts=pts;

    return m_rtpSession.SendPacket(buf,len,m_nPayloadType,marker,incPts);

}


int JRtpSession::RcvData(uint8_t *buf, int len, uint32_t ts,RcvCb rcvCb,void* user)
{
    m_rtpSession.BeginDataAccess();
    if(m_rtpSession.GotoFirstSource()){
        do{
            RTPPacket* pkt;
            while ((pkt=m_rtpSession.GetNextPacket())!=0 && !m_bStopFlag){
                std::cout<<"Got packet with "
                         << "sequence number="<<pkt->GetExtendedSequenceNumber()
                         <<" from SSRC "<<pkt->GetSSRC()
                         <<std::endl;
                rcvCb(pkt->GetPacketData(),pkt->GetPayloadLength(),pkt->HasMarker(),user);
                m_rtpSession.DeletePacket(pkt);
            }

        }while(m_rtpSession.GotoNextSource() && !m_bStopFlag);
    }
    m_rtpSession.EndDataAccess();

    return 0;
}

bool JRtpSession::Stop()
{
    m_bStopFlag=true;
    m_rtpSession.BYEDestroy(0,"time is up",10);
    return true;
}









}//namespace iRtp