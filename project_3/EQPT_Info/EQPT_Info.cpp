#include "EQPT_Info.h"

/*------------------------EQPT_Info_Save------------------------*/
EQPT_Info_Save::EQPT_Info_Save(const char* ip, const char* community)
{
    router_ip = ip;
    router_name = community;

    // SNMP 설정
    snmp_sess_init(&session); 
    session.peername = strdup(ip); 

    // SNMP 버전 설정 (v1, v2c, v3 중 선택) 
    session.version = SNMP_VERSION_2c; // SNMP v2c 

    // 커뮤니티 문자열 설정 
    session.community = (u_char *)community; // public *
    session.community_len = strlen(community);
    session.timeout = 100000L; // 타임아웃 설정 (1초)

    // 세션 열기
    //SOCK_STARTUP;
    session_ptr = snmp_open(&session); 
    if (!session_ptr) // 오류 발생 시
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
EQPT_Info_Save::~EQPT_Info_Save()
{
    // session 정리
    snmp_close(session_ptr);
    //SOCK_CLEANUP;

    // mysql 연결 해제
    mysql_close(conn);

    std::cout << "EQPT_Info_Save 소멸 \n";

}


// DB에 장비정보 저장
int EQPT_Info_Save::eqpt_save_db()
{
    std::string up_time, query, q_val, err_trans_str, server_ip;
    up_time = getCurrentDateTime();

    for (const auto& [mac, eqpt] : mac_eqpt_map) 
    {
        server_ip = router_ip;
        std::replace(server_ip.begin(), server_ip.end(), '.', '_');
        
        query = "INSERT eqpt_info (if_num, up_time, mac, ip, port) VALUE ('" + server_ip + " -" + eqpt[1] + "', '" + up_time + "', ";
        q_val = "";
        
        // 쿼리문 작성
        if(eqpt[2] == "")
        {
            err_trans_str += "-1";
        }
        else
        {
            err_trans_str = eqpt[2];
        }
        q_val += "'" + mac + "', " + "'" + eqpt[0] + "', " + err_trans_str +  ")";
        query += q_val;

        // 쿼리문 실행
        if (mysql_query(conn, query.c_str())) 
        {
            return -1;
        }
    }
    return 0;
}


int EQPT_Info_Save::get_vlan_list(int if_cnt)
{
    struct snmp_pdu *pdu_ptr,  *res_pdu_ptr;
    oid anOID[MAX_OID_LEN]; 
    size_t anOID_len; 
    std::string oid_data_str, if_type_str, check_str;
    int status_num;

    vlan_list_vec.clear();

    snmp_close(session_ptr);

    // SNMP 설정 
    snmp_sess_init(&session); 
    session.peername = strdup(router_ip.c_str()); 

    // SNMP 버전 설정 (v1, v2c, v3 중 선택) 
    session.version = SNMP_VERSION_2c; // SNMP v2c 

    // 커뮤니티 문자열 설정 
    session.community = (u_char *)router_name.c_str(); // public *
    session.community_len = strlen((const char *)session.community);
    session.timeout = 1000000L; // 타임아웃 설정 (1초)

    // 세션 열기
    //SOCK_STARTUP;
    session_ptr = snmp_open(&session); 
    if (!session_ptr) // 오류 발생 시
    { 
        snmp_sess_perror("snmp_open", &session); 
        SOCK_CLEANUP; 
        exit(1); 
    }

    // PDU 생성 및 OID 추가
    anOID_len = MAX_OID_LEN; // OID 길이 조정
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
    read_objid("1.3.6.1.2.1.2.2.1.3", anOID, &anOID_len); 
    snmp_add_null_var(pdu_ptr, anOID, anOID_len); 

    // SNMP 요청 보내기
    {
        std::unique_lock<std::mutex> lock(mtx);
        status_num = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
    }

    if (res_pdu_ptr == nullptr)
    {   
        add_err_log("EQPT_Info_Save", "get_vlan_list : snmp_synch_response err");
    }
    else if ( (status_num == STAT_SUCCESS) && (res_pdu_ptr->errstat == SNMP_ERR_NOERROR) ) 
    {  
        // 결과 값 하나씩 추출해 대조하기
        netsnmp_variable_list *vars = res_pdu_ptr->variables;
        while(vars)
        {
            char oid_buf[1024], val_buf[1024];

            // OID 값 추출
            snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);

            // MIB 확인 / 탈출 처리
            check_str = std::string(oid_buf).substr(20); 
            if (check_str == "4") break;

            // 인터페이스 정보 추출
            oid_data_str = std::string(oid_buf).substr(22); 

            // value 값 추출
            snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);

            // 불필요한 문자 제외 인터페이스 타입 정보 추출
            if_type_str = std::string(val_buf).substr(9); 

            // 만약 VLAN인 경우 리스트에 추가
            if(if_type_str == "53") 
            {
                vlan_list_vec.push_back(oid_data_str);
                //std::cout << "vlan = " << oid_data_str << std::endl;
            }
            vars = vars->next_variable;
        }
    } 
    else 
    { // snmp 요청 실패 처리
        if (status_num == STAT_SUCCESS) 
        {
            add_err_log("EQPT_Info_Save", "get_vlan_list : Error in packet");
        } 
        else if (status_num == STAT_TIMEOUT)
        {
            add_err_log("EQPT_Info_Save", "get_vlan_list : Timeout - No res_pdu_ptr from");
        } 
        else 
        {
            add_err_log("EQPT_Info_Save", "get_vlan_list : snmp_synch_response err");
        }

        return -1;
    }

    return 0;
}


// Mac 주소 리스트를 추출하고 ip, 인터페이스 번호로 매핑
int EQPT_Info_Save::get_eqpt_info()
{
    struct snmp_pdu *pdu_ptr,  *res_pdu_ptr;
    oid anOID[MAX_OID_LEN]; 
    size_t anOID_len; 
    int i, status_num;
    bool loop_b = false;
    std::string oid_data_str, val_data_str, oid_check_str, ip_str, if_num_str;
    std::string req_oid_str = "1.3.6.1.2.1.4.22.1.2";

    // 맵 초기화
    mac_eqpt_map.clear();

    netsnmp_variable_list *vars;

    //std::cout << session_ptr->community << " <- 커뮤니티 이름\n";
    do {
        // PDU 생성 및 OID 추가
        anOID_len = MAX_OID_LEN;
        pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
        pdu_ptr->non_repeaters = 0; 
        pdu_ptr->max_repetitions = 35; // 적절한 값으로 조정
        read_objid(req_oid_str.c_str(), anOID, &anOID_len);
        snmp_add_null_var(pdu_ptr, anOID, anOID_len);

        // SNMP 요청 보내기
        {
            std::unique_lock<std::mutex> lock(mtx);
            status_num = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
        }

        if (res_pdu_ptr == nullptr)
        { 
            add_err_log("EQPT_Info_Save", "get_eqpt_info : snmp_synch_response err");
            return -1;
        }
        // 응답 처리
        else if ( (status_num == STAT_SUCCESS) && (res_pdu_ptr->errstat == SNMP_ERR_NOERROR) ) 
        {   
            // 성공적으로 응답을 받았을 경우 처리
            vars = res_pdu_ptr->variables;
            while(vars)
            {
                char oid_buf[2048],  val_buf[2048];
                // print_variable(vars->name, vars->name_length, vars);

                snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);

                // 현재 MIB 정보 추출
                oid_check_str = std::string(oid_buf).substr(21,1);

                // 원하는 정보가 아닌 경우
                if (oid_check_str != "2")
                {
                    loop_b = true; // 전체 반복 끝내는 신호
                    break;
                }

                // 수집해야 하는 정보인 경우 ip 정보 추출
                oid_data_str = std::string(oid_buf).substr(23); 

                for(i=0 ; i < oid_data_str.size(); i++)
                {
                    if(oid_data_str[i] == '.') break;
                }

                // 인터페이스 번호 추출 (VLAN ver)
                if_num_str = oid_data_str.substr(0,i); 

                // ip 정보 추출
                ip_str = oid_data_str.substr(i+1);

                snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
                val_data_str = std::string(val_buf).substr(12);

                // 맵에 정보 저장
                mac_eqpt_map[val_data_str] = {ip_str, if_num_str};

                // 데이터 이어서 찾기 위한 조치
                if (vars->next_variable == NULL)
                {
                    oid_data_str = std::string(oid_buf); // OID 추출
                    break; 
                }
                vars = vars->next_variable;
            }

            // 반복해야 할 경우 끊긴 데이터에서 그 다음 데이터로 옮기기 위해 OID 업데이트
            if(!loop_b)
            {
                req_oid_str = "1." + oid_data_str.substr(4);
                //std::cout << req_oid_str << " <- OID\n";
            }
        } 
        else 
        { // snmp 응답 실패 처리
            if (status_num == STAT_SUCCESS) 
            {
                add_err_log("EQPT_Info_Save", "get_eqpt_info : Error in packet");
            } 
            else if (status_num == STAT_TIMEOUT) 
            {
                add_err_log("EQPT_Info_Save", "get_eqpt_info : Timeout - No res_pdu_ptr from");
            } 
            else 
            {
                add_err_log("EQPT_Info_Save", "get_eqpt_info : snmp_synch_response err");
            }
            return -1;
        }
    } while(!loop_b);

    return 0;
}


// fast 이더넷 port 정보 가져오기
void EQPT_Info_Save::get_fast_eqpt_port(std::map<std::string, std::string> if_port_map)
{
    std::vector<std::string>::iterator it;

    for (const auto& pair : mac_eqpt_map) 
    {
        it = find(vlan_list_vec.begin(), vlan_list_vec.end(), pair.second[1]);

        if(it == vlan_list_vec.end())
        {
            //std::cout << pair.first << " / " << pair.second[1]  << " / " << if_port_map[pair.second[1]] << std::endl;
            mac_eqpt_map[pair.first].push_back(if_port_map[pair.second[1]]);
        } 
        else
        {
             mac_eqpt_map[pair.first].push_back("0"); 
        }
    } 
}


// vlan 장비 fast 인터페이스 정보 및 port 가져오기
int EQPT_Info_Save::get_vlan_eqpt_port(std::map<std::string, std::string> port_if_map)
{
    int i, vec_cnt, status_num, vlan_cnt = 1; 
    bool loop_b; 
    std::string oid_data_str, val_data_str, oid_check_str_1, oid_check_str_2, ip_str, if_num_str, comm_name; 
    std::string router_vlan_name, req_oid_str = "1.3.6.1.2.1.17.4.3.1.2"; 

    struct snmp_pdu *pdu_ptr,  *res_pdu_ptr;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len; 

    netsnmp_variable_list *vars;

    // vlan 저장된 vector에서 하나씩 불러와 명령
    for(vec_cnt = 0 ; vec_cnt < vlan_list_vec.size() ; vec_cnt ++) 
    {
        loop_b = false;

        router_vlan_name = router_name;
        router_vlan_name += "@" + vlan_list_vec[vec_cnt];
        //std::cout << "vlan_list_vec : " << vlan_list_vec[vec_cnt]  << std::endl;

        // SNMP 설정 
        snmp_close(session_ptr);
        snmp_sess_init(&session); 
        session.peername = strdup(router_ip.c_str()); 
        session.timeout = 100000L;

        // SNMP 버전 설정 (v1, v2c, v3 중 선택) 
        session.version = SNMP_VERSION_2c; // SNMP v2c 

        // 커뮤니티 문자열 설정 
        session.community = (u_char *)router_vlan_name.c_str(); // public *
        session.community_len = strlen((const char *)session.community);
        session.timeout = 1000000L; // 타임아웃 설정 (1초)

        // 세션 열기
        //SOCK_STARTUP;
        session_ptr = snmp_open(&session); 
        if (!session_ptr) // 오류 발생 시
        { 
            snmp_sess_perror("snmp_open", &session); 
            SOCK_CLEANUP; 
            exit(1); 
        }
        //std::cout << "커뮤니티 이름 : " << session_ptr->community << " / "  << router_vlan_name << std::endl;

        do {
            // PDU 생성 및 OID 추가
            anOID_len = MAX_OID_LEN; 
            pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
            pdu_ptr->non_repeaters = 0; 
            pdu_ptr->max_repetitions = 40; // 적절한 값으로 조정
            read_objid(req_oid_str.c_str(), anOID, &anOID_len);
            snmp_add_null_var(pdu_ptr, anOID, anOID_len);

            // SNMP 요청 보내기
            {
                std::unique_lock<std::mutex> lock(mtx);
                status_num = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
            }

            if (res_pdu_ptr == nullptr)
            {   
                add_err_log("EQPT_Info_Save", "get_vlan_eqpt_port : snmp_synch_response err");
                return -1;
                // 지금은 오류를 리턴해 한턴을 통채로 날리지만 5번 재시도 후에 -1을 리턴하도록 변경
            }
            // 응답 처리
            else if ( (status_num == STAT_SUCCESS) && (res_pdu_ptr->errstat == SNMP_ERR_NOERROR) ) 
            {
                vars = res_pdu_ptr->variables;
                while(vars)
                {
                    char oid_buf[2048],  val_buf[2048];

                    // OID 목록에서 맥주소 추출
                    snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);

                    oid_check_str_1 = std::string(oid_buf).substr(23,1);
                    oid_check_str_2 = std::string(oid_buf).substr(19,1);
                    //std::cout << "check : " << oid_check_str <<std::endl;
                    if (oid_check_str_1 != "2" || oid_check_str_2 != "3")
                    {
                        // 현재 MIB 정보 추출
                        //std::cout << oid_buf << std::endl;
                        loop_b = true;
                        break; // MIB 정보가 바뀐 경우 반복 중지
                    }

                    oid_data_str = std::string(oid_buf).substr(25);

                    // 16진수 형태로 가공
                    oid_data_str = convertToHex(oid_data_str);

                    // value 값 추출
                    snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);

                    // 불필요한 문자 제외 포트 정보 추출
                    val_data_str = std::string(val_buf).substr(9);

                    if(mac_eqpt_map[oid_data_str].size() == 0) 
                    {
                        mac_eqpt_map.erase(oid_data_str);

                        if (vars->next_variable == NULL)
                        {
                            oid_data_str = std::string(oid_buf); // OID 추출
                            break;
                        }
                        vars = vars->next_variable;
                        continue;
                    }

                    // port에 맞춰 인터페이스 정보 수정 vlan 인터페이스 -> fast 인터페이스
                    mac_eqpt_map[oid_data_str][1] = std::string(port_if_map[val_data_str]);

                    // port 정보 수정
                    mac_eqpt_map[oid_data_str][2] = val_data_str;
                    //std::cout << mac_eqpt_map[oid_data_str][0] << " / " << mac_eqpt_map[oid_data_str][1]  << " / " << mac_eqpt_map[oid_data_str][2] << std::endl;
        
                    // 데이터 이어서 찾기 위한 조치
                    if (vars->next_variable == NULL)
                    {
                        oid_data_str = std::string(oid_buf); // OID 추출
                        break;
                    }
                    vars = vars->next_variable;
                }

                // 반복해야 할 경우 끊긴 데이터에서 그 다음 데이터로 옮기기 위해 OID 업데이트
                if(!loop_b)
                {
                    req_oid_str = "1." + oid_data_str.substr(4);
                    //std::cout << req_oid_str << " <- OID\n";
                }

            } 
            else // 실패 처리
            {
                if (status_num == STAT_SUCCESS) 
                {
                    add_err_log("EQPT_Info_Save", "get_vlan_eqpt_port : Error in packet");
                } 
                else if (status_num == STAT_TIMEOUT) 
                {
                    add_err_log("EQPT_Info_Save", "get_vlan_eqpt_port : Timeout - No res_pdu_ptr from ");
                } 
                else 
                {
                    add_err_log("EQPT_Info_Save", "get_vlan_eqpt_port : snmp_synch_response err");
                }
                return -1;
            }
        } while(!loop_b);
    } // VLAN for문 종료

    return 0;
}

/*---------------------------------EQPT_Info_Save---------------------------------*/


// 10진수 물리주소를 16진수 물리주소로 변환해주는 함수
std::string convertToHex(const std::string& decimalMAC) 
{

    std::string hexMAC;
    int start = 0, end = decimalMAC.find('.');

    while (end != std::string::npos) 
    {
        int byte = std::stoi(decimalMAC.substr(start, end - start));
        char hex[3];
        sprintf(hex, "%02X", byte);
        hexMAC += hex;
        hexMAC += ' ';
        start = end + 1;
        end = decimalMAC.find('.', start);
    }

    int byte = std::stoi(decimalMAC.substr(start, end - start));
    char hex[3];

    sprintf(hex, "%02X", byte);
    hexMAC += hex;
    return hexMAC + " ";
}


// 나중에 Thread 분리 될 모듈 제어를 위한 함수
void eqpt_save_manger(bool *isLoop_ptr, Interface_Map_Info* if_map_info, EQPT_Info_Save* eqpt_info_save)
{   
    std::map<std::string, std::string> temp_map;
    std::mutex mtx;
    int if_cnt, i;

    while(*isLoop_ptr)
    {   
        for(i = 0; i < 10; i++)
        {
            if(!*isLoop_ptr) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if_cnt = if_map_info->count_interface();

        // 인터페이스 개수 산출 시 오류가 발생한 경우
        if(if_cnt == 0) 
        {
            continue;
        }

        // vlan list 추출하기
        if(eqpt_info_save->get_vlan_list(if_cnt) == -1)
        {
            continue;
        }

        // 장비 ip, mac, 인터페이스 정보 매핑
        if(eqpt_info_save->get_eqpt_info() == -1)
        {
            continue;
        }

        {
            // 인터페이스 - Port 맵 가져오기
            std::unique_lock<std::mutex> lock(mtx);
            temp_map = if_map_info->get_if_port_map(1);
        }
        
        // fast 장비 인터페이스 정보 매핑
        eqpt_info_save->get_fast_eqpt_port(temp_map);
        temp_map.clear();

        {
            // Port - 인터페이스 맵 가져오기
            std::unique_lock<std::mutex> lock(mtx);
            temp_map = if_map_info->get_if_port_map(2);
        }

        // vlan 장비 port 정보 및 인터페이스 정보 매핑
        if(eqpt_info_save->get_vlan_eqpt_port(temp_map) == -1)
        {
            continue;
        }

        // 산출된 트래픽 정보 DB에 저장
        if(eqpt_info_save->eqpt_save_db() == -1)
        {
            continue;
        }
    } // end while 
}


// 맵 출력해보기
void printMap(const std::map<std::string, std::vector<std::string>>& m) 
{
    for (const auto& pair : m) 
    {
        //if(pair.second[2] == "_") continue;
        std::cout << "mac: " << pair.first << "/ ip : ";
        std::cout << pair.second[0] << "    / interface : ";
        std::cout << pair.second[1] << "    / port : ";
        std::cout << pair.second[2];
        std::cout << std::endl;
    }
}



