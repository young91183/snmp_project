#ifndef EQPT_INFO_H
#define EQPT_INFO_H

/*Interface_Info.h에 들어간 정보들*/
//#include "../Interface_Info/Interface_Info.h"

// SNMP 라이브러리
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

// Stream
#include <iostream>
#include <sstream>

// 컨테이너 라이브러리
#include <map>
#include <string>
#include <vector>
#include <algorithm>

// DB 저장
#include <mysql/mysql.h>
#include <chrono>

// Thread
#include <thread>
#include <mutex>

#define ROUTER_IP "10.0.1.254"
//#define ROUTER_NAME "public"
#define ROUTER_NAME "public@101"
/*Interface_Info.h에 들어간 정보들*/

// 장비 정보를 저장하는 모듈
class EQPT_Info_Save 
{ 

    public: 

        explicit EQPT_Info_Save(); // 생성자 snmp pdu, session 초기화
        ~EQPT_Info_Save(); 

        // 생성된 map을 활용해 인터페이스 정보 저장
        void eqpt_save_db();
        void get_vlan_list(int if_cnt); // vlan 리스트 불러오기

        int get_eqpt_info(); // ip, mac, interface 정보 가져오기
        
        // port 정보 가져오기
        void get_fast_eqpt_port(std::map<std::string, std::string> port_if_map);
        int get_vlan_eqpt_port(std::map<std::string, std::string> if_port_map); 
        
    private : 

        // 인터페이스 상태정보 매핑을 위한 map 변수
        std::map<std::string, std::vector<std::string>> mac_eqpt_map;
        std::vector<std::string> vlan_list_vec;

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



// 맵 출력해보는 함수
void printMap(const std::map<std::string, std::vector<std::string>>& m);

//16진수 바꿔주는 함수
std::string convertToHex(const std::string& decimalMAC);

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
void eqpt_save_manger(bool *isLoop_ptr, Interface_Map_Info* if_map_info); 

// 임시 메인 모듈
int main(void); 

#endif //EQPT_INFO_H



