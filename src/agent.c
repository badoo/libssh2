#include "libssh2_priv.h"

#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>

#define SSH2_AGENTC_REQUEST_IDENTITIES 11
#define SSH2_AGENT_IDENTITIES_ANSWER   12
#define SSH_AGENTC_SIGN_REQUEST        13
#define SSH2_AGENT_SIGN_RESPONSE       14

#ifdef LIBSSH2DEBUG
#define UNPRINTABLE_CHAR '.'
static void
debugdump(LIBSSH2_SESSION * session,
          const char *desc, unsigned char *ptr, unsigned long size)
{
    size_t i;
    size_t c;
    FILE *stream = stdout;
    unsigned int width = 0x10;

    if (!(session->showmask & (1 << LIBSSH2_DBG_TRANS))) {
        /* not asked for, bail out */
        return;
    }

    fprintf(stream, "=> %s (%d bytes)\n", desc, (int) size);

    for(i = 0; i < size; i += width) {

        fprintf(stream, "%04lx: ", (long)i);

        /* hex not disabled, show it */
        for(c = 0; c < width; c++) {
            if (i + c < size)
                fprintf(stream, "%02x ", ptr[i + c]);
            else
                fputs("   ", stream);
        }

        for(c = 0; (c < width) && (i + c < size); c++) {
            fprintf(stream, "%c",
                    (ptr[i + c] >= 0x20) &&
                    (ptr[i + c] < 0x80) ? ptr[i + c] : UNPRINTABLE_CHAR);
        }
        fputc('\n', stream);    /* newline */
    }
    fflush(stream);
}
#else
#define debugdump(a,x,y,z)
#endif


static int get_agent_socket(LIBSSH2_SESSION *session)
{
    struct sockaddr_un  sunaddr;
    int                 sock;
    char               *sock_name;

    sock_name = getenv("SSH_AUTH_SOCK");
    if (sock_name == NULL) {
        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "no SSH_AUTH_SOCK set.");
        return -1;
    }
    _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "using %s as agent socket", sock_name);
    _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "method: %.*s",
                   (int)session->userauth_pblc_method_len, session->userauth_pblc_method);
    *session->userauth_pblc_b = 0x01;

    sunaddr.sun_family = AF_UNIX;
    strcpy(sunaddr.sun_path, sock_name);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "sock < 0. Returning.");
        return -1;
    }

    /* TODO: connect may return EINPROGRESS, check it. */
    if (connect(sock, (struct sockaddr *)&sunaddr, sizeof sunaddr) < 0) {
        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "connect < 0. Returning.");
        close(sock);
        return -1;
    }
    return sock;
}

/*
 *
 */
LIBSSH2_API int
libssh2_userauth_sign_with_agent(LIBSSH2_SESSION  *session,
                                 const char       *username,
                                 unsigned int      username_len,
                                 unsigned char   **signature,
                                 unsigned long    *signature_len)
{
    int sock;
    unsigned char       agbuf[4*1024];
    unsigned char       xxx[1024];
    unsigned char      *p;
    int len;
    char *pub_key;
    int pub_key_len;
    int pub_key_cnt;

    /*libssh2_trace(session, 0xFFFFFFFF);*/

    if (session->agent_state == libssh2_NB_state_idle) {
        sock = get_agent_socket(session);
        if (sock < 0)
            return -1;
        session->agent_state = libssh2_NB_state_created;
    }

    /* Get public keys from agent. */
    if (session->agent_state == libssh2_NB_state_created) {
        memset(agbuf, 0, sizeof(agbuf));
        libssh2_htonu32(agbuf, 1);
        agbuf[4] = SSH2_AGENTC_REQUEST_IDENTITIES;
        write(sock, agbuf, 5);
        session->agent_state = libssh2_NB_state_sent1;
    }

    if (session->agent_state == libssh2_NB_state_sent1) {
        read(sock, agbuf, 4);
        len = libssh2_ntohu32(agbuf);
        read(sock, agbuf, len);

        debugdump(session, "pubkey from agent", agbuf, len);

        if (agbuf[0] != SSH2_AGENT_IDENTITIES_ANSWER) {
            _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Bad authentication reply message type: %d", agbuf[0]);
            return -1;
        }
        pub_key_cnt = libssh2_ntohu32(agbuf+1);
        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "found %d keys", pub_key_cnt);
        if (pub_key_cnt == 0) {
            /* No key found. */
            return -1;
        }
        pub_key_len = libssh2_ntohu32(agbuf+5);
        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "pub_key_len %d", pub_key_len);
        pub_key = LIBSSH2_ALLOC(session, pub_key_len);
        memcpy(pub_key, agbuf+9, pub_key_len);

    /* Sign */
        agbuf[0] = SSH_AGENTC_SIGN_REQUEST;
        p = agbuf + 1;

        libssh2_htonu32(p, pub_key_len);
        p += 4;
        libssh2_htonu32(p, session->userauth_pblc_method_len);
        p += 4;
        memcpy(p, session->userauth_pblc_method, session->userauth_pblc_method_len);
        p += session->userauth_pblc_method_len;
        memcpy(p, pub_key+11, pub_key_len-11);
        p += pub_key_len-11;

        len = 4 + session->session_id_len + 1 + 4 + username_len +
            4 + strlen("ssh-connection") + 4 + strlen("publickey") +
            1 + 4 + session->userauth_pblc_method_len +
            4 + pub_key_len - 11 + 4 + session->userauth_pblc_method_len;

        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "len: %d", len);

        libssh2_htonu32(p, len);
        p += 4;

        libssh2_htonu32(p, session->session_id_len);
        p += 4;
        memcpy(p, session->session_id, session->session_id_len);
        p += session->session_id_len;

        *p = SSH_MSG_USERAUTH_REQUEST;
        p++;

        libssh2_htonu32(p, username_len);
        p += 4;
        memcpy(p, username, username_len);
        p += username_len;
        libssh2_htonu32(p, strlen("ssh-connection"));
        p += 4;
        memcpy(p, "ssh-connection", strlen("ssh-connection"));
        p += strlen("ssh-connection");
        libssh2_htonu32(p, strlen("publickey"));
        p += 4;
        memcpy(p, "publickey", strlen("publickey"));
        p += strlen("publickey");
        *p = 1;
        p += 1;

        libssh2_htonu32(p, session->userauth_pblc_method_len);
        p += 4;
        memcpy(p, session->userauth_pblc_method, session->userauth_pblc_method_len);
        p += session->userauth_pblc_method_len;

        libssh2_htonu32(p, pub_key_len);
        p += 4;
        libssh2_htonu32(p, session->userauth_pblc_method_len);
        p += 4;
        memcpy(p, session->userauth_pblc_method, session->userauth_pblc_method_len);
        p += session->userauth_pblc_method_len;
        memcpy(p, pub_key+11, pub_key_len-11);
        p += pub_key_len-11;

        /* Flags. */
        libssh2_htonu32(p, 0);
        p += 4;

        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "len = %d", p - agbuf);
        libssh2_htonu32(xxx, p - agbuf);
        write(sock, xxx, 4);

        len = write(sock, agbuf, p - agbuf);
        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "ret: %d, len: %d", len, p - agbuf);
        session->agent_state = libssh2_NB_state_sent2;
    }

    if (session->agent_state == libssh2_NB_state_sent2) {
        read(sock, agbuf, 4);
        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "%02X %02X %02X %02X",
                       agbuf[0], agbuf[1], agbuf[2], agbuf[3]);
        len = libssh2_ntohu32(agbuf);
        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "ret len: %d", len);
        read(sock, agbuf, len);
        if (agbuf[0] != SSH2_AGENT_SIGN_RESPONSE) {
            _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Agent admitted failure to sign using the key.");
            return -1;
        }

        debugdump(session, "response", agbuf, len);

        if (memcmp(session->userauth_pblc_method, "ssh-dss", session->userauth_pblc_method_len) == 0)
            *signature_len = 40;
        else
            *signature_len = 256;
        _libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "sign_len: %ld", *signature_len);
        *signature = LIBSSH2_ALLOC(session, *signature_len);
        if (!*signature) {
            return -1;
        }

        memcpy(*signature, agbuf+20, *signature_len);
        close(sock);
        LIBSSH2_FREE(session, pub_key);

        libssh2_trace(session, 0);
        return 0;
    }
    return 0;
}

