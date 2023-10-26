//
// Created by sean on 2023/10/16.
//
#include "JRtpSession.h"
#include <atomic>

using namespace jrtplib;

namespace iRtp{

JRtpSession::JRtpSession():m_nPayloadType(0),m_nCurPts(0),m_nSndIncTs(0)
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

    m_sessParams.SetOwnTimestampUnit(1/pInitData->clockRate);

    int status=m_rtpSession.Create(m_sessParams,&m_transParams);
    if(status<0){
        std::cerr<<LOG_FIXED_HEADER()<<RTPGetErrorString(status)<<std::endl;
        return -1;
    }

    unsigned long remoteIp=ntohl(inet_addr(pInitData->remoteIp.data()));
    RTPIPv4Address addr(remoteIp,pInitData->remotePort);
    status=m_rtpSession.AddDestination(addr);
    if(status<0){
        std::cerr<<LOG_FIXED_HEADER()<<RTPGetErrorString(status)<<std::endl;
        return -1;
    }

    m_rtpSession.SetDefaultMark(false);
    m_rtpSession.SetDefaultPayloadType(pInitData->payloadType);

    m_nPayloadType=pInitData->payloadType;
    m_nSndIncTs=pInitData->clockRate/25;

    return true;
}

bool JRtpSession::Start()
{

    return true;
}

int JRtpSession::SendDataWithTs(const uint8_t *buf, int len, uint32_t pts, uint16_t marker)
{

    uint32_t incPts= pts>m_nCurPts ? pts-m_nCurPts : 0;
    m_nCurPts=pts; //caller should make sure that pts dont exceed UINT32_MAX

    return m_rtpSession.SendPacket(buf,len,m_nPayloadType,marker,incPts);

}

int JRtpSession::SendData(const uint8_t *buf, int len, uint16_t marker)
{
    //dont send immediately
//    m_rtpSession.SetDefaultMark(marker!=0);
//    return m_rtpSession.SendPacket(buf,len);
    return SendDataWithTs(buf,len,m_nSndIncTs,marker);

}


int JRtpSession::RcvPayloadData(uint8_t *buf, int len, RcvCb rcvCb, void *user)
{
    m_rtpSession.BeginDataAccess();
    if(m_rtpSession.GotoFirstSource()){
        do{
            RTPPacket* pkt;
            while ((pkt=m_rtpSession.GetNextPacket())!=0 && !m_bStopFlag){
//                std::cout<<"Got packet with "
//                         << "sequence number="<<pkt->GetExtendedSequenceNumber()
//                         <<" from SSRC "<<pkt->GetSSRC()
//                         <<std::endl;
                __updateRtpHeaderData(pkt);
                rcvCb(pkt->GetPayloadData(),pkt->GetPayloadLength(),pkt->HasMarker(),user);
                m_rtpSession.DeletePacket(pkt);
            }

        }while(m_rtpSession.GotoNextSource() && !m_bStopFlag);
    }
    m_rtpSession.EndDataAccess();

    return 0;
}

int JRtpSession::RcvData(uint8_t *buf, int len, RcvCb rcvCb, void *user)
{
    m_rtpSession.BeginDataAccess();
    if(m_rtpSession.GotoFirstSource()){
        do{
            RTPPacket* pkt;
            while ((pkt=m_rtpSession.GetNextPacket())!=0 && !m_bStopFlag){
//                std::cout<<"Got packet with "
//                         << "sequence number="<<pkt->GetExtendedSequenceNumber()
//                         <<" from SSRC "<<pkt->GetSSRC()
//                         <<std::endl;
                __updateRtpHeaderData(pkt);
                rcvCb(pkt->GetPacketData(),pkt->GetPacketLength(),pkt->HasMarker(),user);
                m_rtpSession.DeletePacket(pkt);
            }

        }while(m_rtpSession.GotoNextSource() && !m_bStopFlag);
    }
    m_rtpSession.EndDataAccess();

    return 0;

}

int JRtpSession::RcvDataWithTs(uint8_t *buf, int len, uint32_t ts,RcvCb rcvCb,void* user)
{
    //ignore ts
    return RcvData(buf,len,rcvCb,user);
}

bool JRtpSession::Stop()
{
    m_bStopFlag=true;
    m_rtpSession.BYEDestroy(0,"time is up",10);
    return true;
}



void JRtpSession::__updateRtpHeaderData(jrtplib::RTPPacket* p)
{
    m_rtpHeaderData.pt=p->GetPayloadType();
    m_rtpHeaderData.marker=p->HasMarker();
    m_rtpHeaderData.ssrc=p->GetSSRC();
    m_rtpHeaderData.seq=p->GetSequenceNumber();
    m_rtpHeaderData.ts=p->GetTimestamp();
    m_rtpHeaderData.cc=p->GetCSRCCount();
    m_rtpHeaderData.extension=p->HasExtension();
    for(int i=0;i<m_rtpHeaderData.cc;i++){
        m_rtpHeaderData.csrc[i]=p->GetCSRC(i);
    }
    //just use default
    m_rtpHeaderData.version=2;
    m_rtpHeaderData.padding=0;

}





}//namespace iRtp