#include "./Interface_Info/Interface_Info.h"
#include "./Traffic_Info/Traffic_Info.h"
#include "./EQPT_Info/EQPT_Info.h"

void net_info_save(std::string ip, std::string community, bool * isLoop_ptr)
{
    std::thread interface_thread, traffic_thread, eqpt_thread;
    std::map <std::string, std::string> temp_map;
    Interface_Map_Info* if_map_info = new Interface_Map_Info(ip.c_str(), community.c_str());
    Interface_Info_Save* if_info_save = new Interface_Info_Save(ip.c_str(), community.c_str());
    Traffic_Info_Save* traffic_info_save = new Traffic_Info_Save(ip.c_str(), community.c_str());
    EQPT_Info_Save* eqpt_info_save = new EQPT_Info_Save(ip.c_str(), community.c_str());

    int if_cnt;
    
    // 초기 인터페이스 맵 작성 (활성화 확인)
    if_cnt = if_map_info->count_interface();
    if (if_cnt == 0) 
    {
        // 오류 처리
        std::cout << "count error \n";
        std::cout << ip + "의 라우터 정보 수집 종료\n"; 
        return;
    }

    if (if_map_info->interface_map_renew(if_cnt) == 1)
    {
        // 오류 처리
        std::cout << "interface_map_renew err\n";
        std::cout << ip + "의 라우터 정보 수집 종료\n"; 
        return;
    }

    temp_map = if_map_info->get_if_port_map(1);

    if (if_info_save->state_map_renew(if_cnt) == 1)
    {
        // 오류 처리
        std::cout << "state_map_renew err\n";
        std::cout << ip + "의 라우터 정보 수집 종료\n"; 
        return;
    }

    if (if_info_save->if_name_renew(if_cnt) == 1)
    {
        // 오류 처리
        std::cout << "if_name_renew err\n";
        std::cout << ip + "의 라우터 정보 수집 종료\n"; 
        return;
    }

    // 인터페이스 정보 db에 저장
    if_info_save->ifInfo_save_db(temp_map);

    // 활동 중인 인터페이스 리스트 추출해 저장
    if_map_info->aliveIF_vec_renew(if_info_save->insterface_state_map);

    // Thread 생성 + 객체 이동
    interface_thread = std::thread(interface_save_manger, isLoop_ptr, if_map_info, if_info_save);
    eqpt_thread = std::thread(eqpt_save_manger, isLoop_ptr, if_map_info, eqpt_info_save);
    traffic_thread = std::thread(traffic_save_manger, isLoop_ptr, if_map_info, traffic_info_save);

    while(*isLoop_ptr)
    {   
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // 인터페이스 정보 수집 Thread 종료 대기
    if(interface_thread.joinable())
    {
        interface_thread.join();
    }

    // 장비정보 수집 객체 종료 대기
    if(eqpt_thread.joinable())
    {
        eqpt_thread.join();
    }

    // 장비정보 수집 Thread 종료 대기
    if(traffic_thread.joinable())
    {
        traffic_thread.join();
    }
    std::cout << ip + "의 하위 Thread 동작들 중지 완료\n";

    delete eqpt_info_save; 
    eqpt_info_save = NULL; 

    delete traffic_info_save; 
    traffic_info_save = NULL; 

    delete if_map_info;
    if_map_info = NULL;

    delete if_info_save;
    if_info_save = NULL;

    
    std::cout << ip + "의 객체 소멸 완료\n"; 
    std::cout << ip + "의 라우터 정보 수집 종료\n"; 
}


bool isSnmpValid(const char* ip, const char* community) 
{
    bool isValid;
    struct snmp_session session, *session_ptr;
    struct snmp_pdu *pdu, *response;
    oid name[MAX_OID_LEN]; // OID for sysDescr.0
    size_t name_length = MAX_OID_LEN;
    int status;

    snmp_sess_init(&session); 

    session.peername = strdup(ip);
    session.version = SNMP_VERSION_2c;
    session.community = (u_char*)community;
    session.community_len = strlen(community);
    session.timeout = 1000000L; // 타임아웃 설정 (1초)

    session_ptr = snmp_open(&session);
    if (!session_ptr) 
    {
        return false;
    }

    pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
    pdu->non_repeaters = 0;
    pdu->max_repetitions = 5;
    read_objid("1.3.6.1.2.1.2.2.1.3", name, &name_length);
    snmp_add_null_var(pdu, name, name_length);

    status = snmp_synch_response(session_ptr, pdu, &response);

    if(response != nullptr)
    {
        isValid = (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR);
    }
    else 
    {
        isValid = false;
    }

    if (response)
    {
        snmp_free_pdu(response);
    }
    snmp_close(session_ptr);

    return isValid;
}


// main 함수
int main(void)
{
    SOCK_STARTUP;
    std::cout << "snmp open\n";

    int if_cnt;
    bool isLoop = false, start_sgin = false, ip_comm_check;
    std::string user_req_ip_str, user_req_name, user_req_oper_str;
    std::vector<std::thread> thread_vec;

    while(true)
    {   
        std::cout << "Operate : ";
        std::cin >> user_req_oper_str;

        // 동작 시작 요청인 경우
        if(user_req_oper_str == "start")
        {   
            // 요청 받기
            std::cout << "Request_IP : ";
            std::cin >> user_req_ip_str;
            std::cout << "Community_Name : ";
            std::cin >> user_req_name;

            // ip, 커뮤니티 이름 확인
            ip_comm_check = isSnmpValid(user_req_ip_str.c_str(), user_req_name.c_str());
            if(!ip_comm_check) 
            {
                std::cout << "잘못된 IP와 이름입니다. 다시 입력해 주세요\n";
                continue;
            }
            std::cout << user_req_ip_str + " : 정상 IP \n";

            // 반복문 활성화
            isLoop = true;
            thread_vec.push_back(std::thread(net_info_save, user_req_ip_str.c_str(), user_req_name.c_str(), &isLoop));

            // 시작 신호
            start_sgin = true;
            std::cout << user_req_ip_str + " 네트워크 및 장비 정보 수집 시작 \n";
        }
        // 정상 동작 중지요청 인 경우
        else if(user_req_oper_str == "stop" && start_sgin == true)
        {
            start_sgin = false;

            // thread 종료 신호
            isLoop = false;
            for(auto & net_thread : thread_vec)
            {
                if(net_thread.joinable())
                {
                net_thread .join();
                }
            }
            std::cout << "수집 동작 일시 정지 완료\n";
        }
        // 동작 중지 중인데 중지 요청을 한 경우
        else if(user_req_oper_str == "stop" && start_sgin == false)
        {
            std::cout << "이미 중지 상태입니다. 다른 명령을 요청해주세요.\n";
        }
        // 종료 요청을 한 경우
        else if(user_req_oper_str == "quit")
        {
            // thread 종료 신호 
            isLoop = false;

            // thread 종료 대기
            for(auto & net_thread : thread_vec)
            {
                if(net_thread.joinable())
                {
                    net_thread .join();
                }
            }
            std::cout << "수집 동작 중단 완료\n";
            break;
        }
        else 
        {
            std::cout << "잘못된 요청입니다\n";
        }
    }

    SOCK_CLEANUP;
    std::cout << "snmp 종료\n";
    std::cout << "시스템을 종료합니다.\n";
    return 0;
}




