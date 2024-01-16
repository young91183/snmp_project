#include "./Interface_Info/Interface_Info.h"
#include "./Traffic_Info/Traffic_Info.h"
#include "./EQPT_Info/EQPT_Info.h"

// main 함수
int main(void)
{
    SOCK_STARTUP;
    int if_cnt;
    bool isLoop = false, start_sgin = false;
    std::string user_req_str = "";
    std::thread interface_thread, traffic_thread, eqpt_thread;
    Interface_Map_Info* if_map_info = new Interface_Map_Info();;
    Interface_Info_Save* if_info_save = new Interface_Info_Save();
    std::map <std::string, std::string> temp_map;

    // 초기 인터페이스 맵 작성 (활성화 확인)
    if_cnt = if_map_info->count_interface();
    if (if_cnt == 0) 
    {
        // 오류 처리
        std::cout << "count error \n";
        exit(1); //break로 대체
    }

    if (if_map_info->interface_map_renew(if_cnt) == 1)
    {
        // 오류 처리
        std::cout << "interface_map_renew err\n";
        exit(1); // break로 대체
    }

    /*
    temp_map = if_map_info->get_if_port_map(1);
    for (const auto& pair : temp_map)
    {
        std::cout << "if_port_map :" << pair.first << "/" << pair.second <<"\n";
    }
    */


    if (if_info_save->state_map_renew(if_cnt) == 1)
    {
        // 오류 처리
        std::cout << "state_map_renew err\n";
        exit(1); // break로 대체
    }
    if_map_info->aliveIF_vec_renew(if_info_save->insterface_state_map);
    
    while(true)
    {   
        // 요청 받기
        std::cout << "Request : ";
        std::cin >> user_req_str;

        // 동작 시작 요청인 경우
        if(user_req_str == "start" && start_sgin == false)
        {   
            // 반복문 활성화
            isLoop = true;

            interface_thread = std::thread(interface_save_manger, &isLoop, if_map_info, if_info_save);
            traffic_thread = std::thread(traffic_save_manger, &isLoop, if_map_info);
            eqpt_thread = std::thread(eqpt_save_manger, &isLoop, if_map_info);

            start_sgin = true;
            std::cout << "네트워크 및 장비 정보 수집 시작 \n";
        }
        // 동작 시작 요청인데 이미 동작 중인 경우
        else if(user_req_str == "start" && start_sgin == true)
        {
            std::cout << "이미 동작 상태입니다. 다른 명령을 요청해주세요.\n";
        }
        // 동작 중지요청 인 경우
        else if(user_req_str == "stop" && start_sgin == true)
        {
            start_sgin = false;

            // thread 종료 신호
            isLoop = false;

            // 인터페이스 정보 수집 Thread 종료 대기
            if(interface_thread.joinable())
            {
                interface_thread.join();         
            }
            // 장비정보 수집 Thread 종료 대기
            if(traffic_thread.joinable())
            {
                traffic_thread.join();
            }
            // 장비정보 수집 객체 종료 대기
            if(eqpt_thread.joinable())
            {
                eqpt_thread.join();
            }
            std::cout << "Thread 동작들 중지 완료\n";
            
            
        }
        // 동작 중지 중인데 중지 요청을 한 경우
        else if(user_req_str == "stop" && start_sgin == false)
        {
            std::cout << "이미 중지 상태입니다. 다른 명령을 요청해주세요.\n";
        }
        // 종료 요청을 한 경우
        else if(user_req_str == "quit")
        {
            if(start_sgin == true)
            {
                start_sgin = false;
            }

            // thread 종료 신호 
            isLoop = false;

            // 인터페이스 정보 수집 Thread 종료 대기
            if(interface_thread.joinable())
            {
                interface_thread.join();         
            }
            // 장비정보 수집 Thread 종료 대기
            if(traffic_thread.joinable())
            {
                traffic_thread.join();
            }
            // 장비정보 수집 객체 종료 대기
            if(eqpt_thread.joinable())
            {
                eqpt_thread.join();
            }
            std::cout << "thread 정상 종료 완료\n";
            std::cout<< "Thread 종료 완료\n";
            
            break;
        }
        else 
        {
            std::cout << "잘못된 요청입니다\n";
        }
    }

    delete if_map_info;
    if_map_info = NULL;

    delete if_info_save;
    if_info_save = NULL;
    std::cout << "객체 소멸 완료\n";
    
    SOCK_CLEANUP;
    std::cout << "시스템을 종료합니다.\n";
    return 0;
}
