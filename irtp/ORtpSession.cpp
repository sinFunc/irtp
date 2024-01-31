//
// Created by sean on 2023/8/3.
//

#include "ORtpSession.h"
#include <assert.h>
#include <atomic>
#include <chrono>
#include "ICommon.h"


namespace iRtp{

static std::atomic_int32_t gStaticInitCount(0);

ORtpSession::ORtpSession():m_pRtpSession(nullptr),m_strRemoteIp(""),m_nRemotePort(-1)
    ,m_bIsFirst(true),m_nSndPreviousTs(0),m_nSndIncTs(0)
    ,m_nRcvPreviousTs(0),m_nRcvIncTs(0),m_nRcvSeq(0)
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

    m_strRemoteIp=pData->remoteIp;
    m_nRemotePort=pData->remotePort;

    m_nSndIncTs=m_nRcvIncTs=pData->clockRate/25;

    return true;
}


void ORtpSession::StaticInit()
{
    if(gStaticInitCount<=0)ortp_init();
    ++gStaticInitCount;
}

void ORtpSession::loop()
{
    const int LEN=1500;
    uint8_t buf[LEN];
    while (!m_bStopFlag){
        for(int i=0;i<RTP_MAX_CALLBACK_ITEM_SIZE;i++) {
            RtpRcvCbData pf = m_rtpRcvCbDataArr[i];
            if (!pf.cb)continue;

            switch (i) {
                case pf.ONLY_PAYLOAD:
                    RcvPayloadData(buf,LEN,pf.cb,pf.user);
                    break;
                case pf.WHOLE_PACKET:
                    RcvData(buf,LEN,pf.cb,pf.user);
                    break;
                default:
                    break;
            }//switch

        }//for

    }//while


}


bool ORtpSession::stop()
{
    if(m_pRtpSession){
        rtp_session_destroy(m_pRtpSession);
        m_pRtpSession=nullptr;
    }

    return true;
}




void ORtpSession::StaticUnInit()
{
    --gStaticInitCount;

    if(gStaticInitCount<=0){
        ortp_exit();
        ortp_global_stats_display();
    }

}

int ORtpSession::SendData(const uint8_t *buf, int len, uint16_t marker)
{
    m_nRcvPreviousTs=m_nRcvPreviousTs+m_nSndIncTs>UINT32_MAX ? 0 : m_nRcvPreviousTs+m_nSndIncTs;

    m_pRtpSession->marker=marker;
    return rtp_session_send_with_ts(m_pRtpSession,buf,len,m_nRcvPreviousTs);

}

int ORtpSession::SendDataWithTs(const uint8_t *buf, int len, uint32_t pts, uint16_t marker)
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

int ORtpSession::RcvPayloadData(uint8_t *buf, int len, RcvCb rcvCb, void *user)
{
    int rcvLen=0;
    while (!m_bStopFlag){
        mblk_t* mp= allocb(1500,0);
        if(mp==nullptr){
            std::cout<<LOG_FIXED_HEADER()<<" alloc memory for mp but fails."<<std::endl;
            freeb(mp);
            return 0;
        }

        struct sockaddr_in remoteAddr;
        socklen_t addLen=sizeof(remoteAddr);
        int ret=rtp_session_recvfrom(m_pRtpSession,true,mp,0,(struct sockaddr*)&remoteAddr,&addLen);
        if(ret<=0){
            freeb(mp);
            return rcvLen;
        }

        char* remoteIp= inet_ntoa(remoteAddr.sin_addr);
        int remotePort= htons(remoteAddr.sin_port);
        if(m_strRemoteIp!=std::string(remoteIp) || m_nRemotePort!=remotePort){
            std::cout<<LOG_FIXED_HEADER()<<"The remote peer is not expected."<<remoteIp<<":"<<remotePort<<
                     "expected:"<<m_strRemoteIp<<":"<<m_nRemotePort<<std::endl;
            freeb(mp);
            return 0;
        }

        int header_len=RTP_FIXED_HEADER_SIZE+(rtp_get_cc(mp)*4);
        if(rtp_get_extbit(mp)){
            int extsize= rtp_get_extheader(mp,NULL,NULL);
            if(extsize>=0)header_len+=4+extsize;
        }

        int plen=ret-header_len;
        uint16_t marker=rtp_get_markbit(mp);
        __updateRtpHeaderData(mp);

        memcpy(buf,mp->b_rptr+header_len,plen);
        rcvCb(buf,plen,marker,user);

        freeb(mp);
        rcvLen+=plen;
    }//while

    return rcvLen;

}

int ORtpSession::RcvData(uint8_t *buf, int len, RcvCb rcvCb, void *user)
{

    int rcvLen=0;
    while (!m_bStopFlag){
        mblk_t* mp= allocb(1500,0);
        if(mp==nullptr){
            std::cout<<LOG_FIXED_HEADER()<<" alloc memory for mp but fails."<<std::endl;
            freeb(mp);
            return 0;
        }

        struct sockaddr_in remoteAddr;
        socklen_t addLen=sizeof(remoteAddr);
        int ret=rtp_session_recvfrom(m_pRtpSession,true,mp,0,(struct sockaddr*)&remoteAddr,&addLen);
        if(ret<=0){
            freeb(mp);
            return rcvLen;
        }

        char* remoteIp= inet_ntoa(remoteAddr.sin_addr);
        int remotePort= htons(remoteAddr.sin_port);
        if(m_strRemoteIp!=std::string(remoteIp) || m_nRemotePort!=remotePort){
            std::cout<<LOG_FIXED_HEADER()<<"The remote peer is not expected."<<remoteIp<<":"<<remotePort<<
                     "expected:"<<m_strRemoteIp<<":"<<m_nRemotePort<<std::endl;
            freeb(mp);
            return 0;
        }

        __updateRtpHeaderData(mp);
        uint16_t marker=rtp_get_markbit(mp);

        memcpy(buf,mp->b_rptr,ret);
        rcvCb(buf,ret,marker,user);

        freeb(mp);
        rcvLen+=ret;
    }//while

    return rcvLen;


}

int ORtpSession::RcvDataWithTs(uint8_t *buf, int len, uint32_t ts,RcvCb rcvCb,void* user)
{
    if(len<=0 || buf==nullptr){
        std::cout<<LOG_FIXED_HEADER()<<" The len or buf is invalid."<<std::endl;
        return 0;
    }

    if(m_bIsFirst){
        mblk_t* mp= allocb(1500,0);
        if(mp==nullptr){
           std::cout<<LOG_FIXED_HEADER()<<" alloc memory for mp but fails."<<std::endl;
           freeb(mp);
           return 0;
        }

        struct sockaddr_in remoteAddr;
        socklen_t addLen=sizeof(remoteAddr);
        int ret=rtp_session_recvfrom(m_pRtpSession,true,mp,0,(struct sockaddr*)&remoteAddr,&addLen);
        if(ret<=0){
            freeb(mp);
            return 0;
        }

        char* remoteIp= inet_ntoa(remoteAddr.sin_addr);
        int remotePort= htons(remoteAddr.sin_port);
        if(m_strRemoteIp!=std::string(remoteIp) || m_nRemotePort!=remotePort){
            std::cout<<LOG_FIXED_HEADER()<<"The remote peer is not expected."<<remoteIp<<":"<<remotePort<<
                 "expected:"<<m_strRemoteIp<<":"<<m_nRemotePort<<std::endl;
            freeb(mp);
            return 0;
        }

        int header_len=RTP_FIXED_HEADER_SIZE+(rtp_get_cc(mp)*4);
        if(rtp_get_extbit(mp)){
            int extsize= rtp_get_extheader(mp,NULL,NULL);
            if(extsize>=0)header_len+=4+extsize;
        }

        int plen=ret-header_len;

        uint16_t marker=rtp_get_markbit(mp);
        //m_nCurSeq= rtp_get_seqnumber(mp);
        m_nRcvPreviousTs= rtp_get_timestamp(mp);

        std::cout<<"Got packet with "
                 << "sequence number="<<m_nRcvSeq
                 << " pts="<<m_nRcvPreviousTs
                 <<" from SSRC="<<rtp_get_ssrc(mp)
                 <<std::endl;

        memcpy(buf,mp->b_rptr+header_len,plen);
        rcvCb(buf,plen,marker,user);

        freeb(mp);

        m_bIsFirst=false;
    }//if

    int have_more=1;
    while(!m_bStopFlag && have_more){
        int ret=rtp_session_recv_with_ts(m_pRtpSession,buf,len,m_nRcvPreviousTs,&have_more);
//        if(ret<=0){
//            //std::cout<<"rtp_session_recv_with_ts read data fails"<<std::endl;
//            return 0;
//        }

        mblk_t* mp= rtp_session_recvm_with_ts(m_pRtpSession, m_nRcvPreviousTs);
//        std::cout<<LOG_FIXED_HEADER()<<"the len of payload="<<ret<<std::endl;

//        mblk_t* mp= rtp_session_pick_with_cseq(m_pRtpSession,m_nCurSeq);
        if(mp==nullptr){
//            std::cout<<LOG_FIXED_HEADER()<<"rtp_session_pick_with_cseq fails"<<std::endl;
            m_nRcvPreviousTs= m_nRcvPreviousTs >= UINT32_MAX ? 0 : m_nRcvPreviousTs+m_nRcvIncTs;
//            usleep(1000); //1ms
//            continue;
            return 0;
        }

        rtp_get_payload(mp,&mp->b_rptr);
        int plen=(int)(mp->b_wptr-mp->b_rptr);
        uint16_t marker= rtp_get_markbit(mp);
        uint32_t pts= rtp_get_timestamp(mp);


        std::cout<<"Got packet with "
                 << "sequence number="<<rtp_get_seqnumber(mp)
                 << " pts="<<pts
                 <<" from SSRC="<<rtp_get_ssrc(mp)
                 <<std::endl;

        memcpy(buf,mp->b_rptr,plen);
        rcvCb(buf,plen,marker,user);

        freemsg(mp);

//        ++m_nCurSeq;

    }//while

    return 0;

//    return rtp_session_recv_with_ts(m_pRtpSession,buf,len,ts,&have_more);

}




void ORtpSession::__updateRtpHeaderData(mblk_t *mp)
{
    m_rtpHeaderData.pt= rtp_get_payload_type(mp);
    m_rtpHeaderData.marker=rtp_get_markbit(mp);
    m_rtpHeaderData.ssrc= rtp_get_ssrc(mp);
    m_rtpHeaderData.seq=rtp_get_markbit(mp);
    m_rtpHeaderData.ts= rtp_get_timestamp(mp);
    m_rtpHeaderData.cc= rtp_get_cc(mp);
    m_rtpHeaderData.extension= rtp_get_extbit(mp);
    m_rtpHeaderData.padding= rtp_get_padbit(mp);
    m_rtpHeaderData.version= rtp_get_version(mp);
    for(int i=0;i<m_rtpHeaderData.cc;i++){
        m_rtpHeaderData.csrc[i]= rtp_get_csrc(mp,i);
    }

}










}//namespace iRtp