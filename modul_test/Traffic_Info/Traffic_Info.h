#ifndef TRAFFIC_INFO_H
#define TRAFFIC_INFO_H
/* 인터페이스 모듈에 들어갈 포함목록*/
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <iostream>
#include <sstream>

#include <map>
#include <string>
#include <vector>
#include <algorithm>

#include <mysql/mysql.h>
#include <chrono>

#include <thread>
#include <mutex>

#define ROUTER_IP "10.0.1.254"
#define ROUTER_NAME "public"
/* 인터페이스 모듈에 들어갈 포함목록*/

// #include "../Interface_Info/Inerface_Info.h"
// #include <cmath>


// 인터페이스의 Traffic 정보를 DB에 저장/갱신 하는 모듈
class Traffic_Info_Save 
{ 

    public: 
        explicit Traffic_Info_Save(); // 생성자 snmp pdu, session 초기화
        ~Traffic_Info_Save(); 

        // 생성된 map을 활용해 인터페이스 정보 저장
        void traffic_save_db(std::map<std::string, std::string> if_port_map); 
        int get_bps_info(int if_cnt);
        int get_pps_info(int if_cnt);
        int pps_snmp_operate(std::map<std::string, std::vector<long>> * pps_map, int status_int,  int loop_cnt, int index_num,  double runtime, std::string mib_check_str);
        std::map<std::string, std::vector<std::string>> interface_traffic_map;

    private : 
        // 인터페이스 트래픽 정보 매핑을 위한 map 변수
        std::map<std::string, std::vector<long>> pps_map;
        std::map<std::string, std::vector<long>> bps_map;


        // snmp 관련 변수 
        struct snmp_session session, *session_ptr; 
        struct snmp_pdu *pdu_ptr,  *res_pdu_ptr; 
        oid anOID[MAX_OID_LEN]; 
        size_t anOID_len; 

        // mysql connection 
        const char* mysql_server; 
        const char* user; 
        const char* password; 
        const char* database; 
        MYSQL* conn; 
};




void printMap(const std::map<std::string, std::vector<std::string>>& m);

/*-------------------임시로 가져온 인터페이스 목록 관리 모듈-------------------*/

// 인터페이스 목록을 확인하고 필요한 정보를 mapping해 저장하는 class
class Interface_Map_Info
{
    public : 
        explicit Interface_Map_Info(); // 생성자 snmp pdu, session 초기화
        ~Interface_Map_Info();

        // 초기 맵 생성
        void map_init();
        int interface_map_renew(int if_cnt); // 인터페이스 목록 정보를 갱신

        // 생성된 맵변수를 반환해주는 함수
        std::map<std::string, std::string> get_if_port_map(int req_int); 
        int count_interface();
        
        // 인터페이스, Port 번호가 매핑되어 있는 변수
        std::map<std::string, std::string>  interface_port_map;
        std::map<std::string, std::string>  port_interface_map;

    private : 
        struct snmp_session session, *session_ptr; 
        struct snmp_pdu *pdu_ptr,  *res_pdu_ptr; 
        oid anOID[MAX_OID_LEN]; 
        size_t anOID_len;
        std::mutex mtx;
}; 


/*-------------------임시로 가져온 인터페이스 목록 관리 모듈-------------------*/

// Interface 상태정보 저장 동작을 제어하기 위한 함수 
void traffic_save_manger(bool *isLoop_ptr, Interface_Map_Info* if_map_info);

std::string getCurrentDateTime();

int main(void); // 임시 메인 모듈
#endif //TRAFFIC_INFO_H



/* 무덤
    Traffic_Info_Save
    - public
        int get_bps_info(int if_cnt); 
        int get_pps_info(int if_cnt);
*/
