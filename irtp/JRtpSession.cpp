//
// Created by sean on 2023/10/16.
//
#include "JRtpSession.h"
#include <atomic>
#include "rtpsession.h"
#include "rtpudpv4transmitter.h"
#include "rtpsessionparams.h"
#include "rtpipv4address.h"
#include "rtppacket.h"
#include "rtptimeutilities.h"
#include "rtcpapppacket.h"
#include "rtpinternalsourcedata.h"
#include "rtprawpacket.h"


using namespace jrtplib;

namespace iRtp{

//reDefined JRtp classes
class JRtpSessionImpl:public RTPSession{
public:
    JRtpSessionImpl(JRtpSession* p):m_pRefJRtpSession(p){}

    /** Is called when an incoming RTP packet is about to be processed.
	 *  Is called when an incoming RTP packet is about to be processed. This is _not_
	 *  a good function to process an RTP packet in, in case you want to avoid iterating
	 *  over the sources using the GotoFirst/GotoNext functions. In that case, the
	 *  RTPSession::OnValidatedRTPPacket function should be used.
	 */
    virtual void OnRTPPacket(RTPPacket *pack,const RTPTime &receivetime, const RTPAddress *senderaddress){
          m_pRefJRtpSession->TryToWakeUp();  //notify there is data in the queue

//        std::cout<<LOG_FIXED_HEADER()<<"receive rtp packet"<<std::endl;
    }

    /** Is called when an incoming RTCP packet is about to be processed. */
    virtual void OnRTCPCompoundPacket(RTCPCompoundPacket *pack,const RTPTime &receivetime,
                                      const RTPAddress *senderaddress){
        //provide interface to user to get origin rtcp data
        RtcpRcvCbData* pf=m_pRefJRtpSession->GetRtcpRcvCbData(RtcpRcvCbData::ORIGIN);
        if(!pf->cb){ //ignore.because it is not necessary for application layer
            return;
        }

        pack->GotoFirstPacket(); //reset
        RTCPPacket* rp;
        RtcpPacket d;
        while ((rp=pack->GetNextPacket())!=0){
            d.data=rp->GetPacketData();
            d.dataLen=rp->GetPacketLength();
            pf->cb(&d,pf->user);
        }//while


        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
    }

    /** Is called when an SSRC collision was detected.
     *  Is called when an SSRC collision was detected. The instance \c srcdat is the one present in
     *  the table, the address \c senderaddress is the one that collided with one of the addresses
     *  and \c isrtp indicates against which address of \c srcdat the check failed.
     */
//    virtual void OnSSRCCollision(RTPSourceData *srcdat,const RTPAddress *senderaddress,bool isrtp){
//        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
//    }

    /** Is called when another CNAME was received than the one already present for source \c srcdat. */
//    virtual void OnCNAMECollision(RTPSourceData *srcdat,const RTPAddress *senderaddress,
//                                  const uint8_t *cname,size_t cnamelength){
//        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
//    }

    /** Is called when a new entry \c srcdat is added to the source table. */
//    virtual void OnNewSource(RTPSourceData *srcdat){
//        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
//    }

    /** Is called when the entry \c srcdat is about to be deleted from the source table. */
//    virtual void OnRemoveSource(RTPSourceData *srcdat){
//        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
//    }

    /** Is called when participant \c srcdat is timed out. */
//    virtual void OnTimeout(RTPSourceData *srcdat){
//        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
//    }

    /** Is called when participant \c srcdat is timed after having sent a BYE packet. */
//    virtual void OnBYETimeout(RTPSourceData *srcdat){
//        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
//    }

    /** Is called when an RTCP APP packet \c apppacket has been received at time \c receivetime
     *  from address \c senderaddress.
     */
    virtual void OnAPPPacket(RTCPAPPPacket *apppacket,const RTPTime &receivetime,
                             const RTPAddress *senderaddress){
        RtcpRcvCbData* p=m_pRefJRtpSession->GetRtcpRcvCbData(RtcpRcvCbData::APP_PACKET);
        if(!p->cb){ //ignore.because it is not necessary for application layer
            return;
        }

        RtcpAppPacket d;
        d.appData=apppacket->GetAPPData();
        d.appDataLen=apppacket->GetAPPDataLength();
        d.name=apppacket->GetName();
        d.ssrc=apppacket->GetSSRC();
        d.subType=apppacket->GetSubType();
        //d.packetLen=d.appDataLen+

        p->cb(&d,p->user);

//        std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
    }

    /** Is called when an unknown RTCP packet type was detected. */
    virtual void OnUnknownPacketType(RTCPPacket *rtcppack,const RTPTime &receivetime,
                                     const RTPAddress *senderaddress){
        RtcpRcvCbData* p=m_pRefJRtpSession->GetRtcpRcvCbData(RtcpRcvCbData::UNKNOWN);
        if(!p->cb){ //ignore.because it is not necessary for application layer
            return;
        }

        RtcpUnknownPacket d;
        d.data=rtcppack->GetPacketData();
        d.dataLen=rtcppack->GetPacketLength();
        d.unKnownType=rtcppack->GetPacketType();
        p->cb(&d,p->user);

        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
    }

    /** Is called when an unknown packet format for a known packet type was detected. */
    virtual void OnUnknownPacketFormat(RTCPPacket *rtcppack,const RTPTime &receivetime,
                                       const RTPAddress *senderaddress){
        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
    }

    /** Is called when the SDES NOTE item for source \c srcdat has been timed out. */
//    virtual void OnNoteTimeout(RTPSourceData *srcdat){
//        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
//    }

    /** Is called when an RTCP sender report has been processed for this source. */
    virtual void OnRTCPSenderReport(RTPSourceData *srcdat){
        RtcpRcvCbData* p=m_pRefJRtpSession->GetRtcpRcvCbData(RtcpRcvCbData::SENDER_REPORT);
        if(!p->cb){ //ignore.because it is not necessary for application layer
            return;
        }

        RtcpSRPacket d;
        d.ssrc=srcdat->GetSSRC();
        d.rtpTimeStamp=srcdat->SR_GetRTPTimestamp();
        d.senderOctetCount=srcdat->SR_GetByteCount();
        d.senderPacketCount=srcdat->SR_GetPacketCount();
        d.ntpMSWTimeStamp=srcdat->SR_GetNTPTimestamp().GetMSW();
        d.ntpLSWTimeStamp=srcdat->SR_GetNTPTimestamp().GetLSW();
        p->cb(&d,p->user);

        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
    }



    /** Is called when an RTCP receiver report has been processed for this source. */
    virtual void OnRTCPReceiverReport(RTPSourceData *srcdat){
        RtcpRcvCbData* p=m_pRefJRtpSession->GetRtcpRcvCbData(RtcpRcvCbData::RECEIVER_REPORT);
        if(!p->cb){ //ignore.because it is not necessary for application layer
            return;
        }

        RtcpRRPacket d;
        d.fractionLost=srcdat->RR_GetFractionLost();
        d.lostPacketNumber=srcdat->RR_GetPacketsLost();
        d.extendedHighestSequenceNumber=srcdat->RR_GetExtendedHighestSequenceNumber();
        d.jitter=srcdat->RR_GetJitter();
        d.lastSR=srcdat->RR_GetLastSRTimestamp();
        d.delaySinceLastSR=srcdat->RR_GetDelaySinceLastSR();
        p->cb(&d,p->user);


//        std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
    }

    /** Is called when a specific SDES item was received for this source. */
    //for one item in one chunk. get to know from rtpsources.cpp 464 lines
    //srcdata is the type of RTPInternalSourceData(inherit from RTPSourceData) from rtpsources.cpp 709 lines
    virtual void OnRTCPSDESItem(RTPSourceData *srcdat, RTCPSDESPacket::ItemType t,
                                const void *itemdata, size_t itemlength){
        RtcpRcvCbData* p=m_pRefJRtpSession->GetRtcpRcvCbData(RtcpRcvCbData::SDES_ITEM);
        if(!p->cb){ //ignore.because it is not necessary for application layer
            return;
        }

        RtcpSdesPacket d;
        d.itemData=(uint8_t*)itemdata;
        d.itemDataLen=itemlength;
        d.itemType=(int)t;
        d.ssrc=srcdat->GetSSRC();
        p->cb(&d,p->user);

//        std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
    }

    /** Is called when a specific SDES item of 'private' type was received for this source. */
    //for one item in one chunk. get to know from source code(rtpsources.cpp 464 lines)
    //srcdata is the type of RTPInternalSourceData(inherit from RTPSourceData) from rtpsources.cpp 770 lines
    virtual void OnRTCPSDESPrivateItem(RTPSourceData *srcdat, const void *prefixdata, size_t prefixlen,
                                       const void *valuedata, size_t valuelen){
        RtcpRcvCbData* p=m_pRefJRtpSession->GetRtcpRcvCbData(RtcpRcvCbData::SDES_PRIVATE_ITEM);
        if(!p->cb){ //ignore.because it is not necessary for application layer
            return;
        }

        RtcpSdesPrivatePacket d;
        d.ssrc=srcdat->GetSSRC();
        d.prefixData=(uint8_t*)prefixdata;
        d.prefixDataLength=prefixlen;
        d.valueData=(uint8_t*)valuedata;
        d.valueDataLength=valuelen;
        p->cb(&d,p->user);

    }


    /** Is called when a BYE packet has been processed for source \c srcdat. */
    virtual void OnBYEPacket(RTPSourceData *srcdat){
        RtcpRcvCbData* p=m_pRefJRtpSession->GetRtcpRcvCbData(RtcpRcvCbData::BYE_PACKET);
        if(!p->cb){ //ignore.because it is not necessary for application layer
            return;
        }

        RtcpByePacket d;
        d.ssrc=srcdat->GetSSRC();
        size_t reasonLen;
        d.reasonData=srcdat->GetBYEReason(&reasonLen);
        d.reasonDataLength=reasonLen;
        p->cb(&d,p->user);
//        std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
    }

    /** Is called when an RTCP compound packet has just been sent (useful to inspect outgoing RTCP data). */
//    virtual void OnSendRTCPCompoundPacket(RTCPCompoundPacket *pack){
//        //std::cout<<LOG_FIXED_HEADER()<<"receive rtcp packet in "<<__func__ <<std::endl;
//    }

    /** If RTPSession::SetChangeOutgoingData was sent to true, overriding this you can change the
     *  data packet that will actually be sent, for example adding encryption.
     *  If RTPSession::SetChangeOutgoingData was sent to true, overriding this you can change the
     *  data packet that will actually be sent, for example adding encryption.
     *  Note that no memory management will be performed on the `senddata` pointer you fill in,
     *  so if it needs to be deleted at some point you need to take care of this in some way
     *  yourself, a good way may be to do this in RTPSession::OnSentRTPOrRTCPData. If `senddata` is
     *  set to 0, no packet will be sent out. This also provides a way to turn off sending RTCP
     *  packets if desired. */
    virtual int OnChangeRTPOrRTCPData(const void *origdata, size_t origlen, bool isrtp, void **senddata, size_t *sendlen){
//        std::cout<<LOG_FIXED_HEADER()<<"previous step when send rtp or rtcp data "<<__func__ <<std::endl;
        if(isrtp) {
            (*senddata)=const_cast<void*>(origdata);
            *sendlen=origlen;
        }

        return 0;
    }

    /** This function is called when an RTP or RTCP packet was sent, it can be helpful
    *  when data was allocated in RTPSession::OnChangeRTPOrRTCPData to deallocate it
    *  here. */
    virtual void OnSentRTPOrRTCPData(void *senddata, size_t sendlen, bool isrtp){}

    /** By overriding this function, the raw incoming data can be inspected
     *  and modified (e.g. for encryption).
     *  By overriding this function, the raw incoming data can be inspected
     *  and modified (e.g. for encryption). If the function returns `false`,
     *  the packet is discarded.
     */
    virtual bool OnChangeIncomingData(RTPRawPacket *rawpack){
//        std::cout<<LOG_FIXED_HEADER()<<"receive raw packet "<<__func__ <<std::endl;
        return (!rawpack->IsRTP() && m_pRefJRtpSession->GetDisableRtcp()) ? false : true;
    }


    /*
     * protected interface in RtpSession(jrtplib)
     */
    void SetChangeInData(bool change){ SetChangeIncomingData(change);}
    void SetChangeOutData(bool change){ SetChangeOutgoingData(change);}


private:
    JRtpSession*    m_pRefJRtpSession;


};

class JRTPSessionParams:public RTPSessionParams{};
class JRTPUDPv4TransmissionParams:public RTPUDPv4TransmissionParams{};


JRtpSession::JRtpSession():m_nPayloadType(0),m_nCurPts(0),m_nSndIncTs(0)
    ,m_pRtpSessionImpl(nullptr),m_pSessParams(nullptr),m_pTransParams(nullptr)
{


}

JRtpSession::~JRtpSession()
{
    if(m_pRtpSessionImpl){
        delete m_pRtpSessionImpl;
        m_pRtpSessionImpl=nullptr;
    }
    if(m_pSessParams){
        delete m_pSessParams;
        m_pSessParams=nullptr;
    }
    if(m_pTransParams){
        delete m_pTransParams;
        m_pTransParams=nullptr;
    }

}

bool JRtpSession::Init(const RtpSessionInitData *pInitData)
{

    m_pTransParams=new JRTPUDPv4TransmissionParams();
    unsigned long localIp=ntohl(inet_addr(pInitData->localIp.data()));
    const int  bufSize=2*1024*1024;
    m_pTransParams->SetBindIP(localIp);
    m_pTransParams->SetPortbase(pInitData->localPort);
    m_pTransParams->SetRTPReceiveBuffer(bufSize);

    m_pSessParams=new JRTPSessionParams();
    m_pSessParams->SetOwnTimestampUnit(1/pInitData->clockRate);


    m_pRtpSessionImpl=new JRtpSessionImpl(this);
    int status= m_pRtpSessionImpl->Create(*m_pSessParams,m_pTransParams);
    if(status<0){
        std::cerr<<LOG_FIXED_HEADER()<<RTPGetErrorString(status)<<std::endl;
        return -1;
    }

    unsigned long remoteIp=ntohl(inet_addr(pInitData->remoteIp.data()));
    RTPIPv4Address addr(remoteIp,pInitData->remotePort);
    status=m_pRtpSessionImpl->AddDestination(addr);
    if(status<0){
        std::cerr<<LOG_FIXED_HEADER()<<RTPGetErrorString(status)<<std::endl;
        return -1;
    }

    m_pRtpSessionImpl->SetDefaultMark(false);
    m_pRtpSessionImpl->SetDefaultPayloadType(pInitData->payloadType);

    //set extra params
    auto e=pInitData->GetExtraParamsMap();
    for(auto itr=e.begin();itr!=e.end();++itr){
        const std::string& k=(*itr).first;
        if(k==std::string("receiveBufferSize")){
            int s=atoi((*itr).second.data());
            if(s<=0){
                std::cout<<LOG_FIXED_HEADER()<<" The size of receiveBufSize expected is invalid."<<std::endl;
            } else{
//                std::cout<<LOG_FIXED_HEADER()<<" The size of receiveBufSize="<<s<<std::endl;
                m_pTransParams->SetRTPReceiveBuffer(s);
            }
        }else{
            std::cout<<LOG_FIXED_HEADER()<<" It does not support the key="<<k<<std::endl;
        }

    }

    m_nPayloadType=pInitData->payloadType;
    m_nSndIncTs=pInitData->clockRate/pInitData->fps;

    return true;
}

void JRtpSession::loop()
{
    while (!m_bStopFlag){
        m_pRtpSessionImpl->BeginDataAccess();
        if(m_pRtpSessionImpl->GotoFirstSource()){
            do{
                RTPPacket* pkt;
                while ((pkt=m_pRtpSessionImpl->GetNextPacket())!=0 && !m_bStopFlag){
//                std::cout<<"Got packet with "
//                         << "sequence number="<<pkt->GetExtendedSequenceNumber()
//                         <<" from SSRC "<<pkt->GetSSRC()
//                         <<std::endl;
                    __updateRtpHeaderData(pkt);

                    for(int i=0;i<RTP_MAX_CALLBACK_ITEM_SIZE && !m_bStopFlag;i++){
                        RtpRcvCbData pf=m_rtpRcvCbDataArr[i];
                        if(!pf.cb)continue;

                        switch (i) {
                            case pf.ONLY_PAYLOAD:
                                pf.cb(pkt->GetPayloadData(),pkt->GetPayloadLength(),pkt->HasMarker(),pf.user);
                                break;
                            case pf.WHOLE_PACKET:
                                pf.cb(pkt->GetPacketData(),pkt->GetPacketLength(),pkt->HasMarker(),pf.user);
                                break;
                            default:
                                break;
                        }//switch
                    }//for

                    m_pRtpSessionImpl->DeletePacket(pkt);
                }

            }while(m_pRtpSessionImpl->GotoNextSource() && !m_bStopFlag);
        }
        m_pRtpSessionImpl->EndDataAccess();

        if(!m_bStopFlag) wait(); //for next time

    }//while

    std::cout<<LOG_FIXED_HEADER()<<"The rtp schedule thread quit successfully."<<std::endl;


}

int JRtpSession::SendDataWithTs(const uint8_t *buf, int len, uint32_t pts, uint16_t marker)
{

    uint32_t incPts= pts>m_nCurPts ? pts-m_nCurPts : 0;
    m_nCurPts=pts; //caller should make sure that pts dont exceed UINT32_MAX

    if(incPts>0)m_pRtpSessionImpl->IncrementTimestamp(incPts); //work immediately

    //std::cout<<LOG_FIXED_HEADER()<<"pts="<<pts<<";incPts="<<incPts<<std::endl;

    return m_pRtpSessionImpl->SendPacket(buf,len,m_nPayloadType,marker,0);


}

int JRtpSession::SendData(const uint8_t *buf, int len, uint16_t marker)
{
    uint32_t incPts= marker ? m_nSndIncTs : 0 ;

    m_pRtpSessionImpl->SetDefaultTimestampIncrement(incPts);
    m_pRtpSessionImpl->SetDefaultMark(marker);

    return m_pRtpSessionImpl->SendPacket(buf,len);

}

int JRtpSession::RcvPayloadData(uint8_t *buf, int len, RcvCb rcvCb, void *user)
{
    m_pRtpSessionImpl->BeginDataAccess();
    if(m_pRtpSessionImpl->GotoFirstSource()){
        do{
            RTPPacket* pkt;
            while ((pkt=m_pRtpSessionImpl->GetNextPacket())!=0 && !m_bStopFlag){
//                std::cout<<"Got packet with "
//                         << "sequence number="<<pkt->GetExtendedSequenceNumber()
//                         <<" from SSRC "<<pkt->GetSSRC()
//                         <<std::endl;
                __updateRtpHeaderData(pkt);
                rcvCb(pkt->GetPayloadData(),pkt->GetPayloadLength(),pkt->HasMarker(),user);
                m_pRtpSessionImpl->DeletePacket(pkt);
            }

        }while(m_pRtpSessionImpl->GotoNextSource() && !m_bStopFlag);
    }
    m_pRtpSessionImpl->EndDataAccess();

    return 0;
}

int JRtpSession::RcvData(uint8_t *buf, int len, RcvCb rcvCb, void *user)
{
    m_pRtpSessionImpl->BeginDataAccess();
    if(m_pRtpSessionImpl->GotoFirstSource()){
        do{
            RTPPacket* pkt;
            while ((pkt=m_pRtpSessionImpl->GetNextPacket())!=0 && !m_bStopFlag){
//                std::cout<<"Got packet with "
//                         << "sequence number="<<pkt->GetExtendedSequenceNumber()
//                         <<" from SSRC "<<pkt->GetSSRC()
//                         <<std::endl;
                __updateRtpHeaderData(pkt);
                rcvCb(pkt->GetPacketData(),pkt->GetPacketLength(),pkt->HasMarker(),user);
                m_pRtpSessionImpl->DeletePacket(pkt);
            }

        }while(m_pRtpSessionImpl->GotoNextSource() && !m_bStopFlag);
    }
    m_pRtpSessionImpl->EndDataAccess();

    return 0;

}

int JRtpSession::RcvDataWithTs(uint8_t *buf, int len, uint32_t ts,RcvCb rcvCb,void* user)
{
    //ignore ts
    return RcvData(buf,len,rcvCb,user);
}

bool JRtpSession::stop()
{
    if(m_pRtpSessionImpl){
        m_pRtpSessionImpl->BYEDestroy(0,"time is up",10);
    }

    return true;
}



void JRtpSession::__updateRtpHeaderData(void* p1)
{
    RTPPacket* p=static_cast<RTPPacket*>(p1);
    if(!p){
        std::cout<<LOG_FIXED_HEADER()<<"RtpHeader data is unuseful because the pointer data is invalid."<<std::endl;
        return;
    }

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


int JRtpSession::SendRtcpAppData(uint8_t subType, const uint8_t *name, const void *appData, int appDataLen)
{
    return m_pRtpSessionImpl->SendRTCPAPPPacket(subType,name,appData,appDataLen);

}
int JRtpSession::SendRawData(uint8_t *data, int len, bool isRtp)
{
    return m_pRtpSessionImpl->SendRawData(data,len,isRtp);
}

int JRtpSession::SetSessionBandwidth(double bw)
{
    return m_pRtpSessionImpl->SetSessionBandwidth(bw);
}


void JRtpSession::setDisableRtcp()
{
   m_pRtpSessionImpl->SetChangeInData(m_bDisableRtcp);
   m_pRtpSessionImpl->SetChangeOutData(m_bDisableRtcp);
}





}//namespace iRtp