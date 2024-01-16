    #include "Traffic_Info.h"

    /*------------------------Traffic_Info_Save------------------------*/
    Traffic_Info_Save::Traffic_Info_Save()
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
    { // mysql 커낵션 생성 중 오류 발생 시 처리
        std::cerr << mysql_error(conn) << std::endl; 
        exit(1); 
    }

    }


    // Interface 저장 모듈 소멸자
    Traffic_Info_Save::~Traffic_Info_Save()
    {

    // session 정리
    if (res_pdu_ptr) 
    {
        snmp_free_pdu(res_pdu_ptr);
    }
    snmp_close(session_ptr);
    SOCK_CLEANUP;

    // mysql 연결 해제
    mysql_close(conn);
    std::cout << "Traffic_Info_Save 소멸 \n";

    }


    // DB에 인터페이스 정보 저장/갱신
    void Traffic_Info_Save::traffic_save_db(std::map<std::string, std::string> if_port_map){
    std::string up_time, query, q_val, ip;
    up_time = getCurrentDateTime();

    for (const auto& [if_num, traffic] : interface_traffic_map) 
    {
        if(traffic[0] == "0" || traffic[1] == "0") 
        {
            continue;
        }
        ip = ROUTER_IP;
        std::replace(ip.begin(), ip.end(), '.', '_');
        
        query = "INSERT traffic_info (if_num, up_time, BPS, PPS ) VALUE ('" + ip + " -" + if_num + "', '" + up_time + "', ";; //up_time 추가
        q_val = "";

        // 쿼리문 작성
        q_val += traffic[0] + ", " + traffic[1] + ")";  // up_time 추후 추가
        query += q_val;
        std::cout << query << std::endl;

        // 쿼리문 실행
        if (mysql_query(conn, query.c_str())) 
        { 
            std::cerr <<  mysql_error(conn) << std::endl;
            exit(1);
        }

    }
    }


    // 실제 bps 트래픽 정보 계산
    int Traffic_Info_Save::get_bps_info(int if_cnt)
    {
    int status_int, loop_cnt = 0;
    long int input_bps_l, output_bps_l;
    double input_bps_d, output_bps_d;
    std::string interface_num_str, bps_info_str, check_str;

    std::chrono::system_clock::time_point start_time_in, start_time_out;
    std::chrono::nanoseconds runtime_in, runtime_out;
    double recv_runtime, send_runtime;

    netsnmp_variable_list *vars;

    // 시작 전 맵 정리
    bps_map.clear();

    while(loop_cnt < 2) 
    {

        // 입력 옥텟 정보 추출
        anOID_len = MAX_OID_LEN; // OID 길이 조정
        pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
        pdu_ptr->non_repeaters = 0; 
        pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
        read_objid(".1.3.6.1.2.1.2.2.1.10", anOID, &anOID_len);
        snmp_add_null_var(pdu_ptr, anOID, anOID_len);
        
        // snmp 전송 시간 계산
        if (loop_cnt == 0)
        {
            start_time_in = std::chrono::system_clock::now();
        }
        else
        {
            runtime_in = std::chrono::system_clock::now() - start_time_in ;
            recv_runtime = runtime_in.count();
            recv_runtime = recv_runtime /1000000000;
            std::cout << "시간 (수신) : " << recv_runtime << std::endl;
        }
        // snmp 전송
        status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);

        if (status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) 
        {
            
            vars = res_pdu_ptr->variables;
            while(vars)
            {
                char oid_buf[2048], val_buf[2048];

                // OID 값 추출
                snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
                interface_num_str = std::string(oid_buf).substr(23); // 인터페이스 정보 추출
                check_str = std::string(oid_buf).substr(20, 2);
            
                if (check_str != "10") break;

                // value 값 추출
                snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
                bps_info_str = std::string(val_buf).substr(11); // 불필요한 문자 제외
                input_bps_l = stoll(bps_info_str);
                
                // 첫번째면 수집만
                if(loop_cnt == 0) 
                {
                    bps_map[interface_num_str].push_back(input_bps_l);
                }
                else // 두번째 이상이면
                {   
                    input_bps_d = (input_bps_l - bps_map[interface_num_str][0]) / recv_runtime;
                    // bps_map[interface_num_str][0] = lround(input_bps_d);
                    bps_map[interface_num_str][0] = (long)input_bps_d;
                }
                vars = vars->next_variable;
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
            else // 알수 없는 오류
            {
                snmp_sess_perror("snmp_synch_res", session_ptr);
            }
            return -1;
        }

        // 출력 옥텟 정보 추출 + bps 계산
        anOID_len = MAX_OID_LEN; // OID 길이 조정
        read_objid(".1.3.6.1.2.1.2.2.1.16", anOID, &anOID_len);
        pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
        pdu_ptr->non_repeaters = 0; 
        pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
        snmp_add_null_var(pdu_ptr, anOID, anOID_len);

        // snmp 전송 시간 계산
        if (loop_cnt == 0)
        {
            start_time_out = std::chrono::system_clock::now();
        }
        else
        {
            runtime_out = std::chrono::system_clock::now() - start_time_out;
            send_runtime = runtime_out.count();
            send_runtime = send_runtime / 1000000000;
            std::cout << "시간 (송신) : " << send_runtime << std::endl;
        }

        // snmp 요청 : 송신 buffer
        status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
        if (status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) 
        {
            vars = res_pdu_ptr->variables;
            while(vars)
            {
                char oid_buf[2048], val_buf[2048];

                // OID 값 추출
                snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
                interface_num_str = std::string(oid_buf).substr(23); // 인터페이스 정보 추출
                check_str = std::string(oid_buf).substr(20, 2);

                // MIB 필터
                if(check_str != "16") break;

                // value 값 추출
                snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
                bps_info_str = std::string(val_buf).substr(11); // 불필요한 문자 제외
                output_bps_l = stoll(bps_info_str); // 정수로 변경

                // 첫번째면 입력 옥텟에 + 하기
                if(loop_cnt == 0) 
                {
                    bps_map[interface_num_str].push_back(output_bps_l);
                }
                else // 두번째면 차이를 계산해 interface_traffic_map에 저장
                {
                    output_bps_d = (output_bps_l - bps_map[interface_num_str][1]) / send_runtime;
                    // bps_map[interface_num_str][1] = lround(output_bps_d);
                    bps_map[interface_num_str][1] = (long)output_bps_d;
                    bps_info_str = std::to_string(bps_map[interface_num_str][0] + bps_map[interface_num_str][1]);
                    interface_traffic_map[interface_num_str].push_back(bps_info_str);
                }  
                vars = vars->next_variable;
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
            else // 알수 없는 오류
            {
                snmp_sess_perror("snmp_synch_res", session_ptr);
            }
            return -1;
        }

        loop_cnt ++;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // printMap(interface_traffic_map);
    return 0;

    }

    // 실제 초당 패킷 이동량 확인해 계산하기
    int Traffic_Info_Save::get_pps_info(int if_cnt)
    {
    int status_int,  loop_cnt = 0;
    long int input_pps_l, output_pps_l;
    double input_pps_d, output_pps_d;
    std::string interface_num_str, pps_info_str, check_str;

    // 시간 계산을 위한 변수
    std::vector<std::chrono::system_clock::time_point> start_time_vec;
    std::chrono::nanoseconds runtime_nano_sec; 
    double rTime_d;

    pps_map.clear();

    while(loop_cnt < 2) 
    {   

        /*----- 수신 유니캐스트 패킷 수 계산하기 ------*/
        // PDU 생성 및 OID 추가
        anOID_len = MAX_OID_LEN; // OID 길이 조정
        pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
        pdu_ptr->non_repeaters = 0; 
        pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
        read_objid("1.3.6.1.2.1.2.2.1.11", anOID, &anOID_len);
        snmp_add_null_var(pdu_ptr, anOID, anOID_len);
        
        // snmp 전송 시간 계산
        if (loop_cnt == 0)
        {
            start_time_vec.push_back(std::chrono::system_clock::now());
        }
        else
        {
            runtime_nano_sec = std::chrono::system_clock::now() - start_time_vec[0];
            rTime_d = runtime_nano_sec.count();
            rTime_d = rTime_d / 1000000000;
            std::cout << "유니캐스트 / 시간 (수신) : " << rTime_d << std::endl;
        }

        // snmp 요청
        status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
        if(pps_snmp_operate(&pps_map, status_int, loop_cnt, 0, rTime_d, "11") == -1)
        {
            std::cout << "snmp err 2\n";
        }

        /*------ 송신 유니캐스트 패킷 수 계산하기 -----*/
        // PDU 생성 및 OID 추가
        anOID_len = MAX_OID_LEN; // OID 길이 조정
        pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
        pdu_ptr->non_repeaters = 0; 
        pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
        read_objid("1.3.6.1.2.1.2.2.1.17", anOID, &anOID_len);
        snmp_add_null_var(pdu_ptr, anOID, anOID_len);
        
        // snmp 전송 시간 계산
        if (loop_cnt == 0)
        {
            start_time_vec.push_back(std::chrono::system_clock::now());
        }
        else
        {
            runtime_nano_sec = std::chrono::system_clock::now() - start_time_vec[1];
            rTime_d = runtime_nano_sec.count();
            rTime_d = rTime_d / 1000000000;
            std::cout << "유니캐스트 / 시간 (수신) : " << rTime_d << std::endl;
        }

        // snmp 요청
        status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
        if(pps_snmp_operate(&pps_map, status_int, loop_cnt, 1, rTime_d, "17")== -1)
        {
            std::cout << "snmp err 2\n";
        }

        /*----- 수신 기타 패킷 수 계산하기 -----*/
        // PDU 생성 및 OID 추가
        anOID_len = MAX_OID_LEN; // OID 길이 조정
        pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
        pdu_ptr->non_repeaters = 0; 
        pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
        read_objid("1.3.6.1.2.1.2.2.1.12", anOID, &anOID_len);
        snmp_add_null_var(pdu_ptr, anOID, anOID_len);
        
        // snmp 전송 시간 계산
        if (loop_cnt == 0)
        {
            start_time_vec.push_back(std::chrono::system_clock::now());
        }
        else
        {
            runtime_nano_sec = std::chrono::system_clock::now() - start_time_vec[2];
            rTime_d = runtime_nano_sec.count();
            rTime_d = rTime_d / 1000000000;
            std::cout << "유니캐스트 / 시간 (수신) : " << rTime_d << std::endl;
        }

        // snmp 요청
        status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
        if(pps_snmp_operate(&pps_map, status_int, loop_cnt, 2, rTime_d, "12") == -1)
        {
            std::cout << "snmp err 2\n";
        }

        /*----- 송신 패킷 기타 패킷 수 계산하기 -----*/
        anOID_len = MAX_OID_LEN; // OID 길이 조정
        read_objid("1.3.6.1.2.1.2.2.1.18", anOID, &anOID_len);
        pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
        pdu_ptr->non_repeaters = 0; 
        pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
        snmp_add_null_var(pdu_ptr, anOID, anOID_len);

        // snmp 전송 시간 계산
        if (loop_cnt == 0)
        {
            start_time_vec.push_back(std::chrono::system_clock::now());
        }
        else
        {
            runtime_nano_sec = std::chrono::system_clock::now() - start_time_vec[3];
            rTime_d = runtime_nano_sec.count();
            rTime_d = rTime_d / 1000000000;
            std::cout << "유니캐스트 / 시간 (수신) : " << rTime_d << std::endl;
        }

        // snmp 요청
        status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);
        if(pps_snmp_operate(&pps_map, status_int, loop_cnt, 3, rTime_d, "18") == -1)
        {
            std::cout << "snmp err 2\n";
        }

        // 1초 쉬고 다시 측정
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
        loop_cnt ++;
        std::cout << "loop : " << loop_cnt << std::endl;

    }

    // printMap(interface_traffic_map);
    return 0;
    }


    // pps 처리
    int Traffic_Info_Save::pps_snmp_operate(std::map<std::string, std::vector<long>> * pps_map, int status_int,  int loop_cnt, int index_num,  double runtime, std::string mib_check_str)
    {   
    double pps_d;
    long pps_l;
    // 시간 계산을 위한 변수
    std::string interface_num_str, pps_info_str, check_str;

    netsnmp_variable_list *vars;
    if(status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR)
    { // 정상적으로 요청한 경우
        
        vars = res_pdu_ptr->variables;
        while(vars)
        {
            char oid_buf[1024], val_buf[1024];

            // OID 값 추출
            snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
            interface_num_str = std::string(oid_buf).substr(23); // 인터페이스 정보 추출
            check_str = std::string(oid_buf).substr(20, 2);
        
            if (check_str != mib_check_str) break;

            // value 값 추출
            snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
            pps_info_str = std::string(val_buf).substr(11); // 불필요한 문자 제외
            pps_l = stol(pps_info_str);
            
            // 요청 유형에 따라 다르게 동작
            if(loop_cnt == 0)
            {
                (*pps_map)[interface_num_str].push_back(pps_l);
                //std::cout << "loop_0 - " << index_num  << " | " << interface_num_str << " / " << pps_l << std::endl;
            }
            else if(index_num == 3){
                pps_d = (pps_l - (*pps_map)[interface_num_str][index_num]) / runtime; // 실수 계산
                (*pps_map)[interface_num_str][index_num] = (long)pps_d; // long int로 변환해 저장(소수점 버림)
                pps_info_str = std::to_string((*pps_map)[interface_num_str][0] + (*pps_map)[interface_num_str][1] + (*pps_map)[interface_num_str][2] + (*pps_map)[interface_num_str][3]); // PPS 계산
                interface_traffic_map[interface_num_str].push_back(pps_info_str);
                //std::cout << interface_num_str << " / " << pps_info_str << std::endl;
            }
            else
            {   
                pps_d = (pps_l - (*pps_map)[interface_num_str][index_num]) / runtime;
                // bps_map[interface_num_str][0] = lround(input_bps_d);
                (*pps_map)[interface_num_str][index_num] = (long)pps_d;
                //std::cout << "loop_1 - " << index_num  << " | " << interface_num_str << " / " << pps_l << std::endl;
            }

            vars = vars->next_variable;
        }
    }
    else
    { // snmp 오류 처리
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
        return -1;
    }
    return 0;
    }
    /*------------------------Traffic_Info_Save------------------------*/


    /*-----------------------------트래픽 모듈 핸들러-----------------------------*/

    void traffic_save_manger(bool *isLoop_ptr, Interface_Map_Info* if_map_info){

    // 객체 생성
    Traffic_Info_Save* traffic_info_save = new Traffic_Info_Save();

    std::thread bps_thread, pps_thread;

    std::map<std::string, std::string> temp_map;
    int if_cnt;

    while(*isLoop_ptr)
    {

    // 인터페이스 개수 산출해 가져오기
    if_cnt = if_map_info->count_interface();

    // 인터페이스 개수 산출 시 오류가 발생한 경우
    if (if_cnt == 0) 
    {
        // 오류 처리
        std::cout << "count error \n";
        exit(1); //break로 대체
    }

    // 인터페이스 맵 갱신
    if (if_map_info->interface_map_renew(if_cnt) == 1)
    {
        // 오류 처리
        std::cout << "interface_map_renew err\n";
        exit(1); // break로 대체
    }

    // 인터페이스 맵 복사하기
    temp_map = if_map_info->get_if_port_map(1);


    // 트래픽 정보 산출
    // 맵정리
    traffic_info_save->interface_traffic_map.clear();

    //treaffic 정보 수집 (추후 Thread 분리)
    bps_thread = std::thread(&Traffic_Info_Save::get_bps_info, traffic_info_save, if_cnt);
    pps_thread = std::thread(&Traffic_Info_Save::get_pps_info, traffic_info_save, if_cnt);

    if (traffic_info_save->get_bps_info(if_cnt) == -1)
    {
        // 오류 처리
        std::cout << "state_map_renew err\n";
        exit(1); // break로 대체
    }

    // 정보 저장
    if (traffic_info_save->get_pps_info(if_cnt) == -1)
    {
        // 오류 처리
        std::cout << "state_map_renew err\n";
        exit(1); // break로 대체
    }

    //bps, pps thread 종료 시점까지 대기
    bps_thread.join();
    pps_thread.join();

    // join 문제 없으면 산출된 트래픽 정보 DB에 저장
    traffic_info_save->traffic_save_db(temp_map);

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    delete traffic_info_save; // 객체 삭제
    traffic_info_save = NULL; // 포인터 초기화

    }

    /*-----------------------------트래픽 모듈 핸들러-----------------------------*/

    // 임시 main 함수
    int main(void)
    {
    bool isLoop = false, start_sgin = false;
    std::string user_req_str = "";
    std::thread traffic_thread;

    // 인터페이스 맵 관리 객체 생성
    Interface_Map_Info* if_map_info = new Interface_Map_Info();

    isLoop = true;
    while(isLoop)
    {   
        std::cout << "Request : ";
        std::cin >> user_req_str;

            if(user_req_str == "start" && start_sgin == false)
        {
            traffic_thread = std::thread(traffic_save_manger, &isLoop, if_map_info);
            start_sgin = true;
        } 
        else if(user_req_str == "start" && start_sgin == true)
        {
            std::cout << "이미 동작 상태입니다. 다른 명령을 요청해주세요.\n";
        }
        else if(user_req_str == "stop" && start_sgin == true)
        {
            start_sgin = false;

            // thread 종료 신호
            isLoop = false;

            //thrad 종료 확인 (인터페이스, 장비 모듈도 추가)
            if(traffic_thread.joinable())
            {
                traffic_thread.join();
            }

            // 현재 반복문 재가동
            isLoop = true;

        }
        else if(user_req_str == "stop" && start_sgin == false)
        {
            std::cout << "이미 중지 상태입니다. 다른 명령을 요청해주세요.\n";
        }
        else if(user_req_str == "quit")
        {
            if(start_sgin == true)
            {
                start_sgin = false;
            }

            // thread 종료 신호 
            isLoop = false;

            //thrad 종료 확인 (인터페이스, 장비 모듈도 추가)
            if(traffic_thread.joinable())
            {
                traffic_thread.join();
            }
            break;
        }
        else 
        {
            std::cout << "잘못된 요청입니다\n";
        }

    }

    // 인터페이스 맵 관리 객체 삭제
    delete if_map_info;
    if_map_info = NULL;


    return 0;
    }


    void printMap(const std::map<std::string, std::vector<std::string>>& m) 
    {

    for (const auto& pair : m) 
    {
        std::cout << "Key: " << pair.first << "\nbps : ";
        std::cout << pair.second[0] << "\npps : ";
        std::cout << pair.second[1] << "\n";
    }

    }


    /*

    Traffic 남은 과제 - 90% 완성
    1) pps, bps 계산 모듈 Thread 분리하기 (난이도 하)
    2) 제어모듈 반복문 처리 Test (난이도 하)
    3) 저장 시 현재시간 반영하기 (모듈 결합 시 인터페이스 모듈의 함수 사용)

    */


    /*-------------------임시로 가져온 인터페이스 목록 관리 모듈-------------------*/

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
    int Interface_Map_Info::interface_map_renew(int if_cnt){
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
    int Interface_Map_Info::count_interface(){ 
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






    /*----------------------------무덤----------------------------*/

    /*
    if (traffic_info_save->get_bps_info(if_cnt) == -1){
        // 오류 처리
        std::cout << "state_map_renew err\n";
        exit(1); // break로 대체
    }

    if (traffic_info_save->get_pps_info(if_cnt) == -1){
        // 오류 처리
        std::cout << "state_map_renew err\n";
        exit(1); // break로 대체
    }
    */



    /* // bps 만 계산하기 (실제 속도(최대값))
    // bps 정보 습득해 pps 계산해서 저장하기
    int Traffic_Info_Save::get_traffic_info(int if_cnt){

    int status_int;
    long bps_l;
    double pps_d;
    std::string interface_num_str, bps_info_str, pps_info_str, check_str;

    // 맵 초기화
    interface_traffic_map.clear();

    // 세션 설정 
    session.community = (u_char *)"public";
    session.community_len = strlen((const char *)session.community);

    // PDU 생성 및 OID 추가
    anOID_len = MAX_OID_LEN; // OID 길이 조정
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
    read_objid(".1.3.6.1.2.1.2.2.1.5", anOID, &anOID_len); 
    snmp_add_null_var(pdu_ptr, anOID, anOID_len); 

    status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr); 

    if (status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) { 

        // 결과 값 하나씩 추출해 대조하기
        for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable) {
            char oid_buf[2048], val_buf[2048];

            // OID 값 추출
            snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
            interface_num_str = std::string(oid_buf).substr(22); // 인터페이스 정보 추출
            check_str = std::string(oid_buf).substr(20, 1);
            
            if (check_str == "6") break;

            // value 값 추출
            snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
            bps_info_str = std::string(val_buf).substr(9); // 불필요한 문자 제외 bps 값 추출
            bps_l = std::stoll(bps_info_str);
            pps_d = bps_l/672;
            pps_info_str = std::to_string(pps_d);
            pps_info_str = pps_info_str.substr(0, pps_info_str.size()-4);
            interface_traffic_map[interface_num_str] = {bps_info_str, pps_info_str};
        }

        // 맵 출력해보기
        printMap(interface_traffic_map);

    } else { // 실패 처리
        if (status_int == STAT_SUCCESS) {
            std::cerr << "Error in packet\nReason: " << snmp_errstring(res_pdu_ptr->errstat) << "\n";
        } else if (status_int == STAT_TIMEOUT) {
            std::cerr << "Timeout: No res_pdu_ptr from " << session.peername << "\n";
        } else {
            snmp_sess_perror("snmp_synch_res", session_ptr);
        }
        return -1;
    }

    return 0;

    }

    */


    /*
    int Traffic_Info_Save::get_bps_info(int if_cnt){

    int status_int;
    std::string interface_num_str, bps_info_str, check_str;

    // 맵 초기화
    interface_traffic_map.clear();

    // PDU 생성 및 OID 추가
    anOID_len = MAX_OID_LEN; // OID 길이 조정
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; 
    pdu_ptr->max_repetitions = if_cnt; // 적절한 값으로 조정
    read_objid(".1.3.6.1.2.1.2.2.1.5", anOID, &anOID_len); 
    snmp_add_null_var(pdu_ptr, anOID, anOID_len); 

    status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr); 

    if (status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) { 
        for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable) {
            char oid_buf[2048], val_buf[2048]; 

            // OID 값 추출 
            snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length); 
            interface_num_str = std::string(oid_buf).substr(22); // 인터페이스 정보 추출 
            check_str = std::string(oid_buf).substr(20, 1); 
            
            if (check_str == "6") break; 

            // value 값 추출
            snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars); 
            bps_info_str = std::string(val_buf).substr(9); // 불필요한 문자 제외 
            interface_traffic_map[interface_num_str] = {bps_info_str}; 
        } 
        
    } else { // 실패 처리
        if (status_int == STAT_SUCCESS) { 
            std::cerr << "Error in packet\nReason: " << snmp_errstring(res_pdu_ptr->errstat) << "\n"; 
        } else if (status_int == STAT_TIMEOUT) { 
            std::cerr << "Timeout: No res_pdu_ptr from " << session.peername << "\n"; 
        } else { 
            snmp_sess_perror("snmp_synch_res", session_ptr); 
        } 
        return -1; 
    } 

    return 0;

    }*/
