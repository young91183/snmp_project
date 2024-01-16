#ifndef INTERFACE_INFO_H
#define INTERFACE_INFO_H

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

// 인터페이스 목록을 가져와 인터페이스의 상태정보를 DB에 저장/갱신 하는 모듈
class Interface_Info_Save 
{ 
    public: 
        explicit Interface_Info_Save(); // 생성자 snmp pdu, session 초기화
        ~Interface_Info_Save(); 
        void ifInfo_save_db(std::map<std::string, std::string> if_port_map); // 생성된 map을 활용해 인터페이스 정보 저장
        int state_map_renew(int if_cnt); // 인터페이스 상태정보 맵 갱신
        // 인터페이스 상태정보 매핑을 위한 map 변수
        std::map<std::string, std::string> insterface_state_map;

    private : 
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


// 인터페이스 목록을 확인하고 필요한 정보를 mapping해 저장하는 class
class Interface_Map_Info
{
    public : 
        explicit Interface_Map_Info(); // 생성자 snmp pdu, session 초기화
        ~Interface_Map_Info();
        void map_init();
        int interface_map_renew(int if_cnt); // 인터페이스 목록 정보를 갱신
        std::map<std::string, std::string> get_if_port_map(int req_int); // 생성된 맵변수를 반환해주는 함수
        int count_interface();
        void aliveIF_vec_renew(std::map<std::string, std::string> m);

        // 활성화 인터페이스 목록
        std::vector<std::string> activate_interface_vec;
        
        // 인터페이스, Port 번호가 매핑되어 있는 변수
        std::map<std::string, std::string>  interface_port_map;
        std::map<std::string, std::string>  port_interface_map;

    private : 
        

        // snmp 구조체
        struct snmp_session session, *session_ptr; 
        struct snmp_pdu *pdu_ptr,  *res_pdu_ptr; 
        oid anOID[MAX_OID_LEN]; 
        size_t anOID_len;

        // 뮤텍스
        std::mutex mtx;
}; 

// Interface 상태정보 저장 동작을 제어하기 위한 함수
void interface_save_manger(bool *isLoop_ptr, Interface_Map_Info* if_map_info, Interface_Info_Save* if_info_save ); 

std::string getCurrentDateTime(); // 현재시간 추출 후 Date Time 형식으로 가공해 반환

int main(void); // 임시 메인 모듈

//void printMap(const std::map<std::string, std::string>& m);

#endif //INTERFACE_INFO_H

