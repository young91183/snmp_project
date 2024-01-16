#ifndef EQPT_INFO_H
#define EQPT_INFO_H
#include "../Interface_Info/Interface_Info.h"

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

// 10진수 맥주소 16진수로 바꿔주는 함수
std::string convertToHex(const std::string& decimalMAC);

// Interface 상태정보 저장 동작을 제어하기 위한 함수
void eqpt_save_manger(bool *isLoop_ptr, Interface_Map_Info* if_map_info); 

#endif //EQPT_INFO_H



