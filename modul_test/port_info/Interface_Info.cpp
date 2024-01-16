#include "Interface_Info.h"

/*------------------------Interface_Info_Save------------------------*/

// Interface 저장 모듈 생성자
// SNMP 구조체 초기화, Mysql connection 설정
Interface_Info_Save::Interface_Info_Save(){ 

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
    if (!session_ptr) { 
        snmp_sess_perror("snmp_open", &session); 
        SOCK_CLEANUP; 
        exit(1); 
    }

    // mysql connection 설정 
    mysql_server = "localhost"; 
    user = "root"; 
    password = "0000"; 
    database = "Network_EQPT_Info";  
    conn = mysql_init(NULL); 
    if (!mysql_real_connect(conn, mysql_server, user, password, database, 0, NULL, 0)) { 
        std::cerr << mysql_error(conn) << std::endl; 
        exit(1); 
    }

}


// Interface 저장 모듈 소멸자
Interface_Info_Save::~Interface_Info_Save(){

    // session 정리
    if (res_pdu_ptr) {
        snmp_free_pdu(res_pdu_ptr);
    }
    snmp_close(session_ptr);

    // mysql 연결 해제
    mysql_close(conn);

    std::cout << "Interface_Info_Save 소멸 \n";
}


// DB에 인터페이스 정보 저장/갱신
void Interface_Info_Save::interface_info_save(std::map<std::string, std::string> if_port_map){
    std::string up_time;
    std::string query, q_val, q_dup ;

    for (const auto& [if_num, state] : insterface_state_map) {
        query = "INSERT INTO if_info (if_num, state, up_time) VALUE ";
        q_val = "";
        q_dup = " ON DUPLICATE KEY UPDATE ";
        up_time = getCurrentDateTime();

        // 쿼리문 작성
        q_val += "(" + if_num + ", " + state + ", '" + up_time + "')";
        q_dup += "state = " + state + ", up_time = '" + up_time + "'";
        query += q_val + q_dup;
        
        // 쿼리문 실행
        if (mysql_query(conn, query.c_str())) { 
            std::cerr <<  mysql_error(conn) << std::endl;
            exit(1);
        }
    }
}


// 인터페이스 상태 정보 map 변수 갱신
int Interface_Info_Save::state_map_renew(){

    int if_cnt, status_int;
    std::string interface_num_str, status_str;

    if_cnt = count_interface();
    if(if_cnt == 0 ){
        std::cout << "if_cnt err \n";
        return 0;
    }

    // PDU 생성 및 OID 추가
    anOID_len = MAX_OID_LEN; // OID 길이 조정
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
    read_objid(".1.3.6.1.2.1.2.2.1.8", anOID, &anOID_len);
    snmp_add_null_var(pdu_ptr, anOID, anOID_len);
    
    status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);

    if (status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) {
        for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable) {
            char oid_buf[2048], val_buf[2048];

            // OID 값 추출
            snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
            interface_num_str = std::string(oid_buf).substr(22); // 인터페이스 정보 추출

            // value 값 추출
            snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
            status_str = std::string(val_buf).substr(9, 1); // 불필요한 문자 제외
            //if_status_value = stoi(status_str); // 정수로 변환
            insterface_state_map.insert({interface_num_str, status_str}); // 변수에 저장
        }
    } else { // 오류 처리 
        if (status_int == STAT_SUCCESS) {
            fprintf(stderr, "Error in packet\nReason: %s\n", snmp_errstring(res_pdu_ptr->errstat));
        } else if (status_int == STAT_TIMEOUT) { // 반응이 없을 때
            fprintf(stderr, "Timeout: No response from %s\n", session.peername);
        } else {
            snmp_sess_perror("snmp_synch_response", session_ptr);
        }
    }

    return (status_int == STAT_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
    
}


int Interface_Info_Save::count_interface(){
    int if_cnt = 0, status_int;

    // PDU 생성 및 OID 추가
    anOID_len = MAX_OID_LEN; // OID 길이 조정
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = 100; // 적절한 값으로 조정
    read_objid("1.3.6.1.2.1.17.4.3.1.1", anOID, &anOID_len);
    snmp_add_null_var(pdu_ptr, anOID, anOID_len);

    // SNMP 요청 보내기
    status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
    
    // 응답 처리
    if (status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) {

        // 성공적으로 응답을 받았을 경우 처리
        for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable) {
            if (vars->type == ASN_INTEGER) {
                ++if_cnt;
            }
        }
        return if_cnt;

    } else { // 실패 처리
        if (status_int == STAT_SUCCESS) {
            fprintf(stderr, "Error in packet\nReason: %s\n", snmp_errstring(res_pdu_ptr->errstat));
        } else if (status_int == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No res_pdu_ptr from %s.\n", session.peername);
        } else {
            snmp_sess_perror("snmp_synch_res", session_ptr);
        }
        return 0;
    }

}

/*------------------------Interface_Info_Save------------------------*/


/*------------------------Interface_Map_Info------------------------*/

// Interface Map 정보 생성자
// SNMP 구조체 초기화
Interface_Map_Info::Interface_Map_Info(){

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
    if (!session_ptr) {
        snmp_sess_perror("snmp_open", &session);
        SOCK_CLEANUP;
        exit(1);
    }

}


// 소멸자
Interface_Map_Info::~Interface_Map_Info(){
    
    // session 정리
    if (res_pdu_ptr) {
        snmp_free_pdu(res_pdu_ptr);
    }
    snmp_close(session_ptr);

    std::cout << "Interface_Map_Info 소멸 \n";
}


// 인터페이스 목록 정보를 갱신
int Interface_Map_Info::interface_map_renew(){
    int if_cnt, status_int;
    std::string oid_str, val_str, check_str;

    if_cnt = count_interface();
    if(if_cnt == 0 ){
        std::cout << "if_cnt err \n";
        return 1;
    }

    // PDU 생성 및 OID 추가
    anOID_len = MAX_OID_LEN; // OID 길이 조정
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = 100; // 적절한 값으로 조정
    read_objid("1.3.6.1.4.1.9.5.1.4.1.1.11", anOID, &anOID_len); 
    snmp_add_null_var(pdu_ptr, anOID, anOID_len);
    
    status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);

    if (status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) {
        for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable) {
            char oid_buf[2048], val_buf[2048];

            // OID 값 추출
            snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
            oid_str = std::string(oid_buf).substr(31);
            check_str = std::string(oid_buf).substr(26, 2); // OID 그룹 추출

            // value 값 추출
            snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
            if (vars->type == ASN_INTEGER && check_str == "11" ) { // 원하는 OID 그룹이 확실한 경우
                val_str = std::string(val_buf).substr(9);
                std::cout << "Port = " << oid_str << ", interface = " << val_str << std::endl;
                interface_port_map.insert({oid_str, val_str}); // 변수에 저장
            }
        }
    } else {
        // 오류 처리
        if (status_int == STAT_SUCCESS) {
            fprintf(stderr, "Error in packet\nReason: %s\n", snmp_errstring(res_pdu_ptr->errstat));
        } else if (status_int == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No response from %s\n", session.peername);
        } else {
            snmp_sess_perror("snmp_synch_response", session_ptr);
        }
        return 1;
    }

    return 0;
}


int Interface_Map_Info::count_interface(){
    int if_cnt = 0, status_int;

    // PDU 생성 및 OID 추가
    anOID_len = MAX_OID_LEN; // OID 길이 조정
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = 100; // 적절한 값으로 조정 
    read_objid("1.3.6.1.2.1.17.4.3.1.1", anOID, &anOID_len); 
    snmp_add_null_var(pdu_ptr, anOID, anOID_len); 

    // SNMP 요청 보내기
    status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
    
    // 응답 처리
    if (status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) {

        // 성공적으로 응답을 받았을 경우 처리
        for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable) {
            if (vars->type == ASN_INTEGER) {
                ++if_cnt;
            }
        }
        return if_cnt;

    } else { // 실패 처리
        if (status_int == STAT_SUCCESS) {
            fprintf(stderr, "Error in packet\nReason: %s\n", snmp_errstring(res_pdu_ptr->errstat));
        } else if (status_int == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No res_pdu_ptr from %s.\n", session.peername);
        } else {
            snmp_sess_perror("snmp_synch_res", session_ptr);
        }
        return 0;
    }
}


// 생성된 맵변수를 반환해주는 함수
std::map<std::string, std::string> Interface_Map_Info::get_if_port_map(){
    return interface_port_map;
}

/*------------------------Interface_Map_Info------------------------*/


// 현재시간 추출 후 Date Time 형식으로 가공해 반환
std::string getCurrentDateTime() {
	auto now = std::chrono::system_clock::now();
	std::time_t now_t = std::chrono::system_clock::to_time_t(now);
	std::tm* now_tm = std::localtime(&now_t);

	char buffer[100];
	std::strftime(buffer, 100, "%Y-%m-%d %H:%M:%S", now_tm); // date time 형태로 가공

	return std::string(buffer);
}



// 나중에 Thread 분리 될 모듈 제어를 위한 함수
void interface_save_manger(bool *isLoop_ptr){

    // 객체 생성
    Interface_Map_Info* if_map_info = new Interface_Map_Info();
    Interface_Info_Save* if_info_save = new Interface_Info_Save();

    std::map<std::string, std::string> temp_map;

    // 반복문 삽입 위치
    if (if_map_info->interface_map_renew() == 1){
        std::cout << "interface_map_renew err\n";
        exit(1);
    }
    temp_map = if_map_info->get_if_port_map();

    if (if_info_save->state_map_renew() == 1){
        std::cout << "state_map_renew err\n";
        exit(1);
    }

    if_info_save->interface_info_save(temp_map);

    // 반복문 종료

    delete if_map_info;
    delete if_info_save;
    if_map_info = NULL;
    if_info_save = NULL;
}


// 임시 main 함수
int main(void){
    bool isLoop = false;

    isLoop = true;
    interface_save_manger(&isLoop);

    return 0;
}

