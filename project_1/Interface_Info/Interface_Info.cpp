#include "Interface_Info.h"

/*------------------------Interface_Info_Save------------------------*/

// Interface 저장 모듈 생성자
// SNMP 구조체 초기화, Mysql connection 설정
Interface_Info_Save::Interface_Info_Save()
{ 

    // SNMP 설정 
    snmp_sess_init(&session); 
    session.peername = strdup(ROUTER_IP); 

    // SNMP 버전 설정 (v1, v2c, v3 중 선택) 
    session.version = SNMP_VERSION_2c; // SNMP v2c 

    // 커뮤니티 문자열 설정 
    session.community = (u_char *)ROUTER_NAME; 
    session.community_len = strlen((const char *)session.community);
    session.timeout = 1000000L;

    // 세션 열기
    //SOCK_STARTUP; 
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
    snmp_close(session_ptr);
    //SOCK_CLEANUP;

    // mysql 연결 해제
    mysql_close(conn);

    std::cout << "Interface_Info_Save 소멸 \n";
}


// DB에 인터페이스 정보 저장/갱신
void Interface_Info_Save::ifInfo_save_db(std::map<std::string, std::string> if_port_map)
{
    struct snmp_pdu *pdu_ptr,  *res_pdu_ptr; 
    oid anOID[MAX_OID_LEN]; 
    size_t anOID_len; 
    std::string up_time, query, q_val, q_dup , port, ip, if_name;
    up_time = getCurrentDateTime();

    for (const auto& [if_num, state] : insterface_state_map) 
    {
        query = "INSERT INTO if_info (if_num, if_name, state, port, up_time) VALUE ";
        q_val = "";
        q_dup = " ON DUPLICATE KEY UPDATE ";
        
        port = if_port_map[if_num];
        if_name = insterface_name_map[if_num];
        if (port == "")
        {
            port = "NULL";
        }

        ip = ROUTER_IP;
        std::replace(ip.begin(), ip.end(), '.', '_');
        
        // 쿼리문 작성
        q_val += "('" + ip + " -" + if_num + "', '" + if_name + "', " + state + ", "  + port + ", '" + up_time + "')";
        q_dup += "state = " + state + ", up_time = '" + up_time + "', port = " + port + ", if_name = '" + if_name + "'";
        query += q_val + q_dup;
        
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
    std::unique_lock<std::mutex> lock(mtx);
    struct snmp_pdu *pdu_ptr,  *res_pdu_ptr; 
    oid anOID[MAX_OID_LEN]; 
    size_t anOID_len; 
    int status_num;
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
    netsnmp_variable_list *vars;
    
    //snmp 요청
    status_num = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr); 

    if ( (status_num == STAT_SUCCESS) && (res_pdu_ptr->errstat == SNMP_ERR_NOERROR) ) 
    {
        vars = res_pdu_ptr->variables;
        while(vars)
        {
            char oid_buf[2048], val_buf[2048];

            // OID 값 추출
            snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
            interface_num_str = std::string(oid_buf).substr(22); // 인터페이스 정보 추출

            // value 값 추출
            snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
            status_str = std::string(val_buf).substr(9, 1); // 불필요한 문자 제외
            insterface_state_map.insert({interface_num_str, status_str}); // 변수에 저장
            //std::cout << interface_num_str << " / " << status_str << std::endl;
            vars = vars->next_variable;
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

        if (res_pdu_ptr) 
        {
            snmp_free_pdu(res_pdu_ptr);
        }
        return -1;
    }

    if (res_pdu_ptr) 
    {
        snmp_free_pdu(res_pdu_ptr);
    }

    return 0;
}

// 인터페이스 상태 정보 map 변수 갱신
int Interface_Info_Save::if_name_renew(int if_cnt)
{   
    std::unique_lock<std::mutex> lock(mtx);
    struct snmp_pdu *pdu_ptr,  *res_pdu_ptr; 
    oid anOID[MAX_OID_LEN]; 
    size_t anOID_len; 
    int status_num;
    std::string interface_num_str, name_str, mib_check_str;

    // 맵 초기화
    insterface_name_map.clear();
    
    // PDU 생성 및 OID 추가
    anOID_len = MAX_OID_LEN; // OID 길이 조정
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
    read_objid("1.3.6.1.2.1.2.2.1.2", anOID, &anOID_len); 
    snmp_add_null_var(pdu_ptr, anOID, anOID_len);
    netsnmp_variable_list *vars;
    
    //snmp 요청
    status_num = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr); 

    if ( (status_num == STAT_SUCCESS) && (res_pdu_ptr->errstat == SNMP_ERR_NOERROR) ) 
    {
        vars = res_pdu_ptr->variables;
        while(vars)
        {
            char oid_buf[2048], val_buf[2048];

            // OID 값 추출
            snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
            mib_check_str = std::string(oid_buf).substr(20,1);
            if(mib_check_str != "2") break;

            interface_num_str = std::string(oid_buf).substr(22); // 인터페이스 정보 추출

            // value 값 추출
            snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
            name_str = std::string(val_buf); // 불필요한 문자 제외
            name_str = name_str.substr(9, name_str.size()-10);
            insterface_name_map.insert({interface_num_str, name_str}); // 변수에 저장
            vars = vars->next_variable;
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

        if (res_pdu_ptr) 
        {
            snmp_free_pdu(res_pdu_ptr);
        }
        return -1;
    }

    if (res_pdu_ptr) 
    {
        snmp_free_pdu(res_pdu_ptr);
    }

    return 0;
}

/*------------------------Interface_Info_Save------------------------*/


/*------------------------Interface_Map_Info------------------------*/

// Interface Map 정보 생성자
// SNMP 구조체 초기화
Interface_Map_Info::Interface_Map_Info()
{
    snmp_sess_init(&session);
    session.peername = strdup(ROUTER_IP);

    // SNMP 버전 설정 (v1, v2c, v3 중 선택)
    session.version = SNMP_VERSION_2c; // SNMP v2c

    // 커뮤니티 문자열 설정
    session.community = (u_char *)ROUTER_NAME;
    session.community_len = strlen((const char *)session.community);

    // 세션 열기
    //SOCK_STARTUP;
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
    snmp_close(session_ptr);
    std::cout << "Interface_Map_Info 소멸 \n";
}


// 초기 맵 설정
void Interface_Map_Info::map_init()
{
    struct snmp_pdu *pdu_ptr,  *res_pdu_ptr; 
    oid anOID[MAX_OID_LEN]; 
    size_t anOID_len; 
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
    if ( (status_num == STAT_SUCCESS) && (res_pdu_ptr->errstat == SNMP_ERR_NOERROR) ) 
    {
        netsnmp_variable_list *vars = res_pdu_ptr->variables;
        // 성공적으로 응답을 받았을 경우 처리
        while(vars) 
        {
            if (vars->type == ASN_INTEGER) 
            {
                char val_buf[2048];
                snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
                if_num_str = std::string(val_buf).substr(9); // 불필요한 문자 제외
                interface_port_map.insert({if_num_str, ""}); // 변수에 저장
            }
            vars = vars->next_variable;
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

    if (res_pdu_ptr) 
    {
        snmp_free_pdu(res_pdu_ptr);
    }
}


// 인터페이스 Port 매핑 정보를 갱신 (VLAN 제외)
int Interface_Map_Info::interface_map_renew(int if_cnt)
{
    std::unique_lock<std::mutex> lock(mtx);
    struct snmp_pdu *pdu_ptr,  *res_pdu_ptr; 
    oid anOID[MAX_OID_LEN]; 
    size_t anOID_len; 
    int status_num;
    std::string oid_str, val_str, check_str;

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
        if ( (status_num == STAT_SUCCESS) && (res_pdu_ptr->errstat == SNMP_ERR_NOERROR) ) 
        {
            netsnmp_variable_list *vars = res_pdu_ptr->variables;
            while(vars)
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
                vars = vars->next_variable;
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

            if (res_pdu_ptr) 
            {
                snmp_free_pdu(res_pdu_ptr);
            }
            return 1;
        }
    
    if (res_pdu_ptr) 
    {
        snmp_free_pdu(res_pdu_ptr);
    }
    return 0;
}

void Interface_Map_Info::aliveIF_vec_renew(std::map<std::string, std::string> m){
    std::unique_lock<std::mutex> lock(mtx);
    activate_interface_vec.clear();
    for(const auto& pair : m)
    {
        if(pair.second == "1")
        {
            activate_interface_vec.push_back(pair.first);
            //std::cout << pair.first << " / " << pair.second << std::endl;
        }
    }
}

// 인터페이스 개수 반환 (VLAN 포함)
int Interface_Map_Info::count_interface()
{ 
    std::unique_lock<std::mutex> lock(mtx);
    struct snmp_pdu *pdu_ptr,  *res_pdu_ptr; 
    oid anOID[MAX_OID_LEN]; 
    size_t anOID_len; 
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
    if ( (status_num == STAT_SUCCESS) && (res_pdu_ptr->errstat == SNMP_ERR_NOERROR) ) 
    {
        // 성공적으로 응답을 받았을 경우 처리
        netsnmp_variable_list *vars = res_pdu_ptr->variables;
        while(vars) 
        {
            if (vars->type == ASN_INTEGER) 
            {
                ++if_cnt;
            }
            vars = vars->next_variable;
        }

        if (res_pdu_ptr) 
        {
            snmp_free_pdu(res_pdu_ptr);
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
        /*for(const auto &pair : interface_port_map) 
        {
            std::cout << "Key: " << pair.first << " Value: " << pair.second << "\n";
        }*/
        return interface_port_map;
    }
    else if(req_int == 2)
    { // port 번호가 key인 맵 반환
        /*for(const auto &pair :  port_interface_map) 
        {
            std::cout << "Key: " << pair.first << " Value: " << pair.second << "\n";
        }*/
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
void interface_save_manger(bool *isLoop_ptr, Interface_Map_Info* if_map_info, Interface_Info_Save* if_info_save)
{
    std::map<std::string, std::string> temp_map;
    std::mutex mtx;

    int if_cnt, i;

    while(*isLoop_ptr)
    {
        {
            // 인터페이스 개수 산출해 가져오기
            std::unique_lock<std::mutex> lock(mtx); 
            if_cnt = if_map_info->count_interface();
        }

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

        {
            // 인터페이스 - Port 맵 가져오기
            std::unique_lock<std::mutex> lock(mtx);
            temp_map = if_map_info->get_if_port_map(1);
        }

        if (if_info_save->state_map_renew(if_cnt) == 1)
        {
            // 오류 처리
            std::cout << "state_map_renew err\n";
            exit(1); // break로 대체
        }

        if (if_info_save->if_name_renew(if_cnt) == 1)
        {
            // 오류 처리
            std::cout << "state_map_renew err\n";
            exit(1); // break로 대체
        }

        // 활동 중인 인터페이스 리스트 추출해 저장
        if_map_info->aliveIF_vec_renew(if_info_save->insterface_state_map);

        // 인터페이스 정보 db에 저장
        if_info_save->ifInfo_save_db(temp_map);

        for(i = 0; i < 30; i++)
        {
            if(!*isLoop_ptr) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

/*

Interface 남은 과제 - 95% 완성
1) 10002번 (4번포트) <- 얘 뭐하는 애인지 알아보기

*/
