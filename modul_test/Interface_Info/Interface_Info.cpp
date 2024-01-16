#include "Interface_Info.h"

/*------------------------Interface_Info_Save------------------------*/

// Interface 저장 모듈 생성자
// SNMP 구조체 초기화, Mysql connection 설정
Interface_Info_Save::Interface_Info_Save()
{ 

    // SNMP 설정 
    anOID_len = MAX_OID_LEN; 
    snmp_sess_init(&session); 
    session.peername = strdup(ROUTER_IP); 

    // SNMP 버전 설정 (v1, v2c, v3 중 선택) 
    session.version = SNMP_VERSION_2c; // SNMP v2c 

    // 커뮤니티 문자열 설정 
    session.community = (u_char *)ROUTER_NAME; 
    session.community_len = strlen((const char *)session.community); 

    // 세션 열기
    SOCK_STARTUP; 
    session_ptr = snmp_open(&session); 
    if (!session_ptr) 
    { 
        snmp_sess_perror("snmp_open", &session); 
        SOCK_CLEANUP; 
        exit(1); 
    }

    // mysql connection 설정 
    mysql_server = "localhost"; 
    user = "root"; 
    password = "0000"; 
    database = "net_info";  
    conn = mysql_init(NULL); 
    if (!mysql_real_connect(conn, mysql_server, user, password, database, 0, NULL, 0)) 
    { 
        std::cerr << mysql_error(conn) << std::endl; 
        exit(1); 
    }

}


// Interface 저장 모듈 소멸자
Interface_Info_Save::~Interface_Info_Save()
{
    // session 정리
    if (res_pdu_ptr) 
    {
        snmp_free_pdu(res_pdu_ptr);
    }
    snmp_close(session_ptr);

    // mysql 연결 해제
    mysql_close(conn);

    std::cout << "Interface_Info_Save 소멸 \n";
}


// DB에 인터페이스 정보 저장/갱신
void Interface_Info_Save::ifInfo_save_db(std::map<std::string, std::string> if_port_map)
{
    std::string up_time, query, q_val, q_dup , port, ip;
    up_time = getCurrentDateTime();

    for (const auto& [if_num, state] : insterface_state_map) 
    {
        query = "INSERT INTO if_info (if_num, state, port, up_time) VALUE ";
        q_val = "";
        q_dup = " ON DUPLICATE KEY UPDATE ";
        
        port = if_port_map[if_num];
        if (port == "")
            port = "NULL";
        
        ip = ROUTER_IP;
        std::replace(ip.begin(), ip.end(), '.', '_');
        
        // 쿼리문 작성
        q_val += "('" + ip + " -" + if_num + "', " + state + ", "  + port + ", '" + up_time + "')";
        q_dup += "state = " + state + ", up_time = '" + up_time + "', port = " + port;
        query += q_val + q_dup;
        //std::cout << query << std::endl;
        
        // 쿼리문 실행
        if (mysql_query(conn, query.c_str())) 
        { 
            std::cerr <<  mysql_error(conn) << std::endl;
            exit(1);
        }
    }
}


// 인터페이스 상태 정보 map 변수 갱신
int Interface_Info_Save::state_map_renew(int if_cnt)
{

    int status_int;
    std::string interface_num_str, status_str;

    // 맵 초기화
    insterface_state_map.clear();
    
    // PDU 생성 및 OID 추가
    anOID_len = MAX_OID_LEN; // OID 길이 조정
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
    read_objid(".1.3.6.1.2.1.2.2.1.8", anOID, &anOID_len); 
    snmp_add_null_var(pdu_ptr, anOID, anOID_len); 
    
    //snmp 요청
    status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr); 

    if (status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) 
    {

        for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable) 
        {
            char oid_buf[2048], val_buf[2048];

            // OID 값 추출
            snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
            interface_num_str = std::string(oid_buf).substr(22); // 인터페이스 정보 추출

            // value 값 추출
            snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
            status_str = std::string(val_buf).substr(9, 1); // 불필요한 문자 제외
            insterface_state_map.insert({interface_num_str, status_str}); // 변수에 저장
        }

    } 
    else 
    { // 실패 처리
        if (status_int == STAT_SUCCESS) 
        {
            std::cerr << "Error in packet\nReason: " << snmp_errstring(res_pdu_ptr->errstat) << "\n";
        } 
        else if (status_int == STAT_TIMEOUT) 
        {
            std::cerr << "Timeout: No res_pdu_ptr from " << session.peername << "\n";
        } 
        else 
        {
            snmp_sess_perror("snmp_synch_res", session_ptr);
        }
    }

    return (status_int == STAT_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
    
}

/*------------------------Interface_Info_Save------------------------*/


/*------------------------Interface_Map_Info------------------------*/

// Interface Map 정보 생성자
// SNMP 구조체 초기화
Interface_Map_Info::Interface_Map_Info()
{

    anOID_len = MAX_OID_LEN;
    snmp_sess_init(&session);
    session.peername = strdup(ROUTER_IP);

    // SNMP 버전 설정 (v1, v2c, v3 중 선택)
    session.version = SNMP_VERSION_2c; // SNMP v2c

    // 커뮤니티 문자열 설정
    session.community = (u_char *)ROUTER_NAME;
    session.community_len = strlen((const char *)session.community);

    // 세션 열기
    SOCK_STARTUP;
    session_ptr = snmp_open(&session);
    if (!session_ptr) 
    {
        snmp_sess_perror("snmp_open", &session);
        SOCK_CLEANUP;
        exit(1);
    }

}


// 소멸자
Interface_Map_Info::~Interface_Map_Info()
{
    
    // session 정리
    if (res_pdu_ptr) 
    {
        snmp_free_pdu(res_pdu_ptr);
    }
    snmp_close(session_ptr);
    std::cout << "Interface_Map_Info 소멸 \n";

}


// 초기 맵 설정
void Interface_Map_Info::map_init()
{

    std::string if_num_str;
    int status_num;

    anOID_len = MAX_OID_LEN; // OID 길이 조정
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = 100; // 적절한 값으로 조정
    read_objid("1.3.6.1.2.1.2.2.1.1", anOID, &anOID_len); 
    snmp_add_null_var(pdu_ptr, anOID, anOID_len);

    // SNMP 요청 보내기
    status_num = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
    
    // 응답 처리
    if (status_num == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) 
    {

        // 성공적으로 응답을 받았을 경우 처리
        for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable) 
        {

            if (vars->type == ASN_INTEGER) 
            {
                char val_buf[2048];
                snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
                if_num_str = std::string(val_buf).substr(9); // 불필요한 문자 제외
                interface_port_map.insert({if_num_str, ""}); // 변수에 저장
            }

        }

    } 
    else 
    { // 실패 처리

        if (status_num == STAT_SUCCESS) 
        {
            std::cerr << "Error in packet\nReason: " << snmp_errstring(res_pdu_ptr->errstat) << "\n";
        } 
        else if (status_num == STAT_TIMEOUT) 
        {
            std::cerr << "Timeout: No res_pdu_ptr from " << session.peername << "\n";
        } 
        else 
        {
            snmp_sess_perror("snmp_synch_res", session_ptr);
        }

    }

}


// 인터페이스 Port 매핑 정보를 갱신 (VLAN 제외)
int Interface_Map_Info::interface_map_renew(int if_cnt)
{
    int status_num;
    std::string oid_str, val_str, check_str;

    { // 뮤텍스 범위
        std::unique_lock<std::mutex> lock(mtx);

        // map 초기화
        interface_port_map.clear();
        port_interface_map.clear();
        map_init();

        // PDU 생성 및 OID 추가
        anOID_len = MAX_OID_LEN; // OID 길이 조정
        pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
        pdu_ptr->non_repeaters = 0; 
        pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
        read_objid("1.3.6.1.4.1.9.5.1.4.1.1.11", anOID, &anOID_len); 
        snmp_add_null_var(pdu_ptr, anOID, anOID_len);
        
        status_num = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);

        // 정상적으로 결과를 반환한 경우
        if (status_num == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) 
        {
                
            for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable)
             {
                char oid_buf[2048], val_buf[2048];
                
                // OID 값 추출
                snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
                oid_str = std::string(oid_buf).substr(31);
                check_str = std::string(oid_buf).substr(26, 2); // OID 그룹 추출

                // value 값 추출
                snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
                if (vars->type == ASN_INTEGER && check_str == "11") 
                {

                    // 원하는 정보만 필터
                    val_str = std::string(val_buf).substr(9);
                    
                    // 맵 갱신
                    port_interface_map[oid_str] = val_str; 
                    interface_port_map[val_str] = oid_str; 

                }
            
            }

        } 
        else 
        { // 실패 처리
            if (status_num == STAT_SUCCESS) 
            {
                std::cerr << "Error in packet\nReason: " << snmp_errstring(res_pdu_ptr->errstat) << "\n";
            } 
            else if (status_num == STAT_TIMEOUT) 
            {
                std::cerr << "Timeout: No res_pdu_ptr from " << session.peername << "\n";
            } 
            else 
            {
                snmp_sess_perror("snmp_synch_res", session_ptr);
            }
            return 1;
        }
    }

    return 0;
}


// 인터페이스 개수 반환 (VLAN 포함)
int Interface_Map_Info::count_interface()
{ 
    int if_cnt = 0, status_num; 

    // PDU 생성 및 OID 추가 
    anOID_len = MAX_OID_LEN; // OID 길이 조정 
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용 
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = 100; // 적절한 값으로 조정 
    read_objid("1.3.6.1.2.1.2.2.1.1", anOID, &anOID_len); 
    snmp_add_null_var(pdu_ptr, anOID, anOID_len); 

    // SNMP 요청 보내기
    status_num = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
    
    // 응답 처리
    if (status_num == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) 
    {

        // 성공적으로 응답을 받았을 경우 처리
        for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable) 
        {
            if (vars->type == ASN_INTEGER) 
            {
                ++if_cnt;
            }
        }
        
        return if_cnt;
    } 
    else 
    { // 실패 처리
        if (status_num == STAT_SUCCESS) 
        {
            std::cerr << "Error in packet\nReason: " << snmp_errstring(res_pdu_ptr->errstat) << "\n";
        } 
        else if (status_num == STAT_TIMEOUT) 
        {
            std::cerr << "Timeout: No res_pdu_ptr from " << session.peername << "\n";
        } 
        else 
        {
            snmp_sess_perror("snmp_synch_res", session_ptr);
        }
        return 0;
    }

}


// 생성된 맵변수를 반환해주는 함수
std::map<std::string, std::string> Interface_Map_Info::get_if_port_map(int req_int)
{

    if (req_int == 1) // 인터페이스 번호가 키인 맵 반환
    { 
        for(const auto &pair : interface_port_map) 
        {
            std::cout << "Key: " << pair.first << " Value: " << pair.second << "\n";
        }
        return interface_port_map;
    }
    else if(req_int == 2)
    { // port 번호가 key인 맵 반환
        for(const auto &pair : port_interface_map) 
        {
            std::cout << "Key: " << pair.first << " Value: " << pair.second << "\n";
        }
        return port_interface_map;
    } 
    else 
    {
        std::cout << "잘못된 맵 요청 기본 맵 반환 \n";
        return interface_port_map;
    }

}

/*------------------------Interface_Map_Info------------------------*/

// 현재시간 추출 후 Date Time 형식으로 가공해 반환
std::string getCurrentDateTime() 
{
    char buffer[100];
	auto now = std::chrono::system_clock::now();
	std::time_t now_t = std::chrono::system_clock::to_time_t(now);
	std::tm* now_tm = std::localtime(&now_t);

	std::strftime(buffer, 100, "%Y-%m-%d %H:%M:%S", now_tm); // date time 형태로 가공

	return std::string(buffer);
}


// 나중에 Thread 분리 될 모듈 제어를 위한 함수
void interface_save_manger(bool *isLoop_ptr)
{

    // 객체 생성
    Interface_Map_Info* if_map_info = new Interface_Map_Info();
    Interface_Info_Save* if_info_save = new Interface_Info_Save();

    std::map<std::string, std::string> temp_map;

    int if_cnt;

    
    // 반복문 삽입 위치

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
    temp_map = if_map_info->get_if_port_map(1);

    if (if_info_save->state_map_renew(if_cnt) == 1)
    {
        // 오류 처리
        std::cout << "state_map_renew err\n";
        exit(1); // break로 대체
    }

    if_info_save->ifInfo_save_db(temp_map);

    // 반복문 종료

    delete if_map_info;
    delete if_info_save;
    if_map_info = NULL;
    if_info_save = NULL;
}


// 임시 main 함수
int main(void)
{
    bool isLoop = false;
    isLoop = true;

    // Thread 분리
    interface_save_manger(&isLoop);

    return 0;
}


/*

Interface 남은 과제 - 90% 완성
1) 인터페이스 리스트 모듈 수정해서 활성화 된 모듈의 목록 제공될 수 있도록 수정
2) 10002번 (4번포트) <- 얘 뭐하는 애인지 알아보기

*/


/*
void printMap(const std::map<std::string, std::string>& m) {
    for (const auto& pair : m) {
        std::cout << "Key: " << pair.first << ", Value: " << pair.second << std::endl;
    }
}
*/
