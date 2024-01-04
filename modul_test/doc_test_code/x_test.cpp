#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <iostream>
#include <sstream>

int main() {
    struct snmp_session session, *session_ptr;
    struct snmp_pdu *pdu_ptr;
    struct snmp_pdu *res_pdu_ptr;

    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;

    snmp_sess_init(&session);  // 구조체 초기화
    session.peername = strdup("10.0.1.254");

    // SNMP 버전 설정 (v1, v2c, v3 중 선택)
    session.version = SNMP_VERSION_2c; // SNMP v2c

    // 커뮤니티 문자열 설정
    session.community = (u_char *)"public";
    session.community_len = strlen((const char *)session.community);

    // 세션 열기
    SOCK_STARTUP;
    session_ptr = snmp_open(&session);
    if (!session_ptr) {
        snmp_sess_perror("snmp_open", &session);
        SOCK_CLEANUP;
        exit(1);
    }

    // PDU 생성 및 OID 추가
    pdu_ptr = snmp_pdu_create(SNMP_MSG_GETBULK); // GETBULK 요청 사용
    pdu_ptr->non_repeaters = 0; // 통상적으로 0으로 설정합니다.
    pdu_ptr->max_repetitions = 1000; // 적절한 값으로 조정
    read_objid("1.3.6.1.2.1.17.4.3.1.1", anOID, &anOID_len);

    snmp_add_null_var(pdu_ptr, anOID, anOID_len);

    // SNMP 요청 보내기
    int status_int = snmp_synch_response(session_ptr, pdu_ptr, &res_pdu_ptr);

    // 응답 처리
    if (status_int == STAT_SUCCESS && res_pdu_ptr->errstat == SNMP_ERR_NOERROR) {

        // 성공적으로 응답을 받았을 경우 처리
        for(netsnmp_variable_list *vars = res_pdu_ptr->variables; vars; vars = vars->next_variable) {
            print_variable(vars->name, vars->name_length, vars);
        }

    } else {
        // 실패 처리
        if (status_int == STAT_SUCCESS) {
            fprintf(stderr, "Error in packet\nReason: %s\n", snmp_errstring(res_pdu_ptr->errstat));
        } else if (status_int == STAT_TIMEOUT) {
            fprintf(stderr, "Timeout: No res_pdu_ptr from %s.\n", session.peername);
        } else {
            snmp_sess_perror("snmp_synch_res", session_ptr);
        }
    }

    // 세션 정리
    if (res_pdu_ptr) {
        snmp_free_pdu(res_pdu_ptr);
    }
    snmp_close(session_ptr);

    SOCK_CLEANUP;
    return (status_int == STAT_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
