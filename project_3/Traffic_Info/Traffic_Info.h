#ifndef TRAFFIC_INFO_H
#define TRAFFIC_INFO_H
#include "../Interface_Info/Interface_Info.h"
//#include <condition_variable>
// #include <cmath>


// 인터페이스의 Traffic 정보를 DB에 저장/갱신 하는 모듈
class Traffic_Info_Save 
{ 
    public: 
        explicit Traffic_Info_Save(const char* ip, const char* community); // 생성자 snmp pdu, session 초기화
        ~Traffic_Info_Save(); 

        // 생성된 map을 활용해 인터페이스 정보 저장
        int traffic_save_db(std::map<std::string, std::string> if_port_map); 
        int get_bps_info(int if_cnt);
        int get_pps_info(int if_cnt);
        void traffic_map_combine();
        int pps_snmp_operate(int status_int,  int loop_cnt, int index_num,  double runtime, std::string mib_check_str, struct snmp_pdu *res_pdu_ptr);
        std::map<std::string, std::vector<std::string>> interface_traffic_map;

    private : 
        // 인터페이스 트래픽 정보 매핑을 위한 map 변수
        std::map<std::string, std::vector<long>> pps_map;
        std::map<std::string, std::vector<long>> bps_map;

        //mutex
        std::mutex mtx;

        // snmp 관련 변수 
        struct snmp_session session, *session_ptr;
        std::string router_ip, router_name;

        // mysql connection 
        const char* mysql_server; 
        const char* user; 
        const char* password; 
        const char* database; 
        MYSQL* conn; 
};

// Interface 상태정보 저장 동작을 제어하기 위한 함수 
void traffic_save_manger(bool *isLoop_ptr, Interface_Map_Info* if_map_info, Traffic_Info_Save* traffic_info_save);

//int main(void); // 임시 메인 모듈

//void printMap(const std::map<std::string, std::vector<std::string>>& m);
#endif //TRAFFIC_INFO_H


