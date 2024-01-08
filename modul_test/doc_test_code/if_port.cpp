#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <iostream>
#include <sstream>


int main() {
    struct snmp_session session, *session_ptr;
    struct snmp_pdu *pdu_ptr, *response_ptr;

    std::string oid_str, val_str, check_str; 
    
    int status, if_count = 0, if_num;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;

    snmp_sess_init(&session);  // 세션 구조체 초기화
    session.peername = strdup("10.0.1.254");
    session.version = SNMP_VERSION_2c; // SNMP 버전 설정
    session.community = (u_char *)"public";
    session.community_len = strlen((const char *)session.community);

    SOCK_STARTUP;
    session_ptr = snmp_open(&session);
    if (!session_ptr) {
        snmp_sess_perror("snmp_open", &session);
        SOCK_CLEANUP;
        exit(1);
    }

    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK);
    pdu_ptr->non_repeaters = 0;
    pdu_ptr->max_repetitions = 100; // 임의의 큰 수로 설정하여 인터페이스 개수를 가져옴
    
    read_objid(".1.3.6.1.2.1.2.2.1.1", anOID, &anOID_len); // ifIndex OID 입력
    snmp_add_null_var(pdu_ptr, anOID, anOID_len);

    // SNMP 요청 보내기
    status = snmp_synch_response(session_ptr, pdu_ptr, &response_ptr);

    // 응답 처리
    if (status == STAT_SUCCESS && response_ptr->errstat == SNMP_ERR_NOERROR) {
        netsnmp_variable_list *vars;
        for(vars = response_ptr->variables; vars; vars = vars->next_variable) {
            
            if (vars->type == ASN_INTEGER) {
                ++if_count;
            }
        }


        pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK);
        pdu_ptr->non_repeaters = 0;
        pdu_ptr->max_repetitions = if_count;

        // ifOperStatus OID 입력
        anOID_len = MAX_OID_LEN;
        read_objid("1.3.6.1.4.1.9.5.1.4.1.1.11", anOID, &anOID_len); 
        snmp_add_null_var(pdu_ptr, anOID, anOID_len);
        status = snmp_synch_response(session_ptr, pdu_ptr, &response_ptr);
        

        if (status == STAT_SUCCESS && response_ptr->errstat == SNMP_ERR_NOERROR) {
            for(vars = response_ptr->variables; vars; vars = vars->next_variable) {
                char oid_buf[2048], val_buf[2048];
                snprint_objid(oid_buf, sizeof(oid_buf), vars->name, vars->name_length);
                oid_str = std::string(oid_buf).substr(31);
                check_str = std::string(oid_buf).substr(26, 2); // OID 그룹 추출

                snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
                if (vars->type == ASN_INTEGER && check_str == "11" ) { // 원하는 OID 그룹이 확실한 경우
                    val_str = std::string(val_buf).substr(9);
                    if_num = stoi(val_str);
                    std::cout << "Port = " << oid_str << ", State = " << if_num << std::endl;
                }
            }
        }
    } else {
        // 오류 처리
        if (status == STAT_SUCCESS) {
            fprintf(stderr, "Error in packet\nReason: %s\n", snmp_errstring(response_ptr->errstat));
        } else if (status == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No response from %s\n", session.peername);
        } else {
            snmp_sess_perror("snmp_synch_response", session_ptr);
        }
    }

    // 세션 정리
    if (response_ptr) snmp_free_pdu(response_ptr);
    snmp_close(session_ptr);
    SOCK_CLEANUP;
    return (status == STAT_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
