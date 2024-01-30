//
// Created by sean on 2024/1/29.
//

#ifndef IRTP_RTPSCHEDULE_H
#define IRTP_RTPSCHEDULE_H

#include "ICommon.h"
#include <thread>
#include <atomic>
#include <condition_variable>

namespace iRtp{

class RtpSchedule {
public:
    RtpSchedule();
    ~RtpSchedule();




private:
    std::condition_variable m_cv;
    std::mutex              m_mutex;
    std::atomic_bool        m_isWaking;
    std::atomic_bool        m_bStopFlag;
    std::thread*            m_pThread;
};

}//namespace iRtp
#endif //IRTP_RTPSCHEDULE_H
