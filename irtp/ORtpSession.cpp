//
// Created by sean on 2023/8/3.
//

#include "ORtpSession.h"
#include <assert.h>


namespace iRtp{

std::atomic_int32_t  ORtpSession::m_staInitCount(0);

ORtpSession::ORtpSession():m_pRtpSession(nullptr)
{
    StaticInit(); //init if necessary
}

ORtpSession::~ORtpSession() noexcept
{
    StaticUnInit();

}

bool ORtpSession::Init(const RtpSessionInitData *pData)
{
    assert(pData);

    if(m_pRtpSession){
        std::cout<<LOG_FIXED_HEADER()<<" It already init"<<std::endl;
        return false;
    }

    m_pRtpSession= rtp_session_new(RTP_SESSION_SENDRECV);
    if(m_pRtpSession==nullptr){
        std::cout<<LOG_FIXED_HEADER()<<" Create rtpSession fail"<<std::endl;
        return false;
    }
    if(rtp_session_set_local_addr(m_pRtpSession,pData->localIp.data(),pData->localPort,pData->localPort+1)<0){
        std::cout<<LOG_FIXED_HEADER()<<" Setting rtpSession local addr fails"<<std::endl;
        return false;
    }
    if(rtp_session_set_remote_addr(m_pRtpSession,pData->remoteIp.data(),pData->remotePort)<0){
        std::cout<<LOG_FIXED_HEADER()<<" Setting rtpSession remote addr fails"<<std::endl;
        return false;
    }

    rtp_profile_set_payload(&av_profile,pData->payloadType,&payload_type_h264); //add to map

    if(rtp_session_set_payload_type(m_pRtpSession,pData->payloadType)<0){
        std::cout<<LOG_FIXED_HEADER()<<" Setting rtpSession payload type fails"<<std::endl;
        return false;
    }

    return true;
}


void ORtpSession::StaticInit()
{
    if(m_staInitCount<=0)ortp_init();
    ++m_staInitCount;
}

bool ORtpSession::Start()
{

    return true;
}


bool ORtpSession::Stop()
{
    m_bStopFlag=true;

    if(m_pRtpSession){
        rtp_session_destroy(m_pRtpSession);
        m_pRtpSession=nullptr;
    }

    return true;
}




void ORtpSession::StaticUnInit()
{
    --m_staInitCount;

    if(m_staInitCount<=0){
        ortp_exit();
        ortp_global_stats_display();
    }

}

int ORtpSession::SendData(const uint8_t *buf, int len, uint32_t pts, uint64_t marker)
{

    if(len<=0){
        std::cout<<LOG_FIXED_HEADER()<<" The len is invalid."<<std::endl;
        return len;
    }

    m_pRtpSession->marker=marker;
    int realLen=rtp_session_send_with_ts(m_pRtpSession,buf,len,pts);

    if(realLen<=0){
        std::cout<<LOG_FIXED_HEADER()<<"Try to send rtp data but fails."<<std::endl;
    }

    return realLen;

}

int ORtpSession::RcvData(uint8_t *buf, int len, uint32_t ts,RcvCb rcvCb,void* user)
{
    if(len<=0 || buf==nullptr){
        std::cout<<LOG_FIXED_HEADER()<<" The len or buf is invalid."<<std::endl;
        return 0;
    }

    int have_more=1;

    while(!m_bStopFlag && have_more){
        if(rtp_session_recv_with_ts(m_pRtpSession,buf,len,ts,&have_more)>0){
            rcvCb(buf,len,have_more,user);
        }

    }//while

    return 0;

//    return rtp_session_recv_with_ts(m_pRtpSession,buf,len,ts,&have_more);

}















}//namespace iRtp