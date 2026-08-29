/* pam_totp.c  Modulo PAM de segundo factor TOTP
 *
 * Opciones en /etc/pam.d/<servicio>:
 * debug     registra el flujo en syslog (nunca el seed ni el codigo)
 * nullok    si el usuario no tiene 2FA, abstenerse en vez de denegar
 *
 * Retornos:
 * PAM_SUCCESS           codigo (o codigo de recuperacion) valido
 * PAM_AUTH_ERR          codigo invalido, reusado, limitado, o sin 2FA estando nullok desactivado
 * PAM_IGNORE            sin 2FA y con nullok
 * PAM_USER_UNKNOWN      no se pudo resolver el usuario
 * PAM_CONV_ERR          la aplicacion no pudo pedir el codigo
 * PAM_AUTHINFO_UNAVAIL  parametros o estado ilegibles o inseguros
 */

#define _GNU_SOURCE
#define PAM_SM_AUTH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <limits.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>
#include "totp_common.h"

#define CODE_PROMPT "Codigo de verificacion: "

/* bajada de privilegios:
 * El modulo corre como root dentro de sshd, pero el archivo esta en el
 * home del usuario. Bajamos el euid/egid antes de tocarlo para que el
 * kernel aplique los permisos del usuario y no los de root.
 *
 * Devuelve 0 si bajo privilegios, 1 si no hacia falta, -1 si fallo.
 */
static int drop_privs(pam_handle_t *pamh, uid_t uid, gid_t gid, uid_t *ouid, gid_t *ogid) {
    *ouid = geteuid();
    *ogid = getegid();

    if (*ouid != 0) return 1;

    if (setegid(gid) != 0) {
        pam_syslog(pamh, LOG_ERR, "setegid fallo: %s", strerror(errno));
        return -1;
    }
    if (seteuid(uid) != 0) {
        pam_syslog(pamh, LOG_ERR, "seteuid fallo: %s", strerror(errno));
        if (setegid(*ogid) != 0) _exit(1);
        return -1;
    }
    return 0;
}

/* restaura los privilegios antiguos */
static void restore_privs(uid_t ouid, gid_t ogid) {
    if (seteuid(ouid) != 0 || setegid(ogid) != 0) _exit(1);
}

/* pide el codigo a traves de la funcion de conversacion de PAM */
static int ask_code(pam_handle_t *pamh, char **out) {
    const struct pam_conv *conv = NULL;
    struct pam_message msg;
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;

    *out = NULL;

    if (pam_get_item(pamh, PAM_CONV, (const void **) &conv) != PAM_SUCCESS
        || conv == NULL || conv->conv == NULL)
        return PAM_CONV_ERR;

    memset(&msg, 0, sizeof msg);
    msg.msg_style = PAM_PROMPT_ECHO_OFF;  /* no mostrar lo que se escribe */
    msg.msg = CODE_PROMPT;

    if (conv->conv(1, &msgp, &resp, conv->appdata_ptr) != PAM_SUCCESS || resp == NULL)
        return PAM_CONV_ERR;

    if (resp[0].resp == NULL) {  /* si no escribe nada */
        free(resp);
        return PAM_CONV_ERR;
    }

    *out = resp[0].resp;   /* nos quedamos con el string */
    free(resp);            /* liberamos el arreglo */
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    totp_params_t params;
    totp_cfg_t cfg;
    const char *user = NULL;
    struct passwd *pw;
    char path[PATH_MAX];
    char *code = NULL;
    totp_err_t terr;
    uid_t ouid;
    gid_t ogid;
    int dropped, debug = 0, nullok = 0, i;
    int64_t matched = 0;
    int used_scratch = 0, need_save = 0;
    time_t now;
    int rc;

    (void) flags;

    /* leemos las opciones de modulo */
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) debug = 1;
        else if (strcmp(argv[i], "nullok") == 0) nullok = 1;
        else pam_syslog(pamh, LOG_WARNING, "opcion desconocida: %s", argv[i]);
    }

    /* parametros del algoritmo */
    terr = totp_params_load(TOTP_CONF, &params);
    if (terr != TOTP_OK) {
        /* si el archivo es inseguro o invalido no autenticamos */
        pam_syslog(pamh, LOG_ERR, "parametros invalidos en %s: %s", TOTP_CONF, totp_strerror(terr));
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* usuario y ruta */
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL)
        return PAM_USER_UNKNOWN;

    /* obtiene datos del usuario */
    pw = pam_modutil_getpwnam(pamh, user);
    if (pw == NULL) {
        pam_syslog(pamh, LOG_ERR, "usuario desconocido: %s", user);
        return PAM_USER_UNKNOWN;
    }

    if (totp_path(path, sizeof path, pw->pw_dir) != 0) return PAM_AUTHINFO_UNAVAIL;

    if (debug)
        pam_syslog(pamh, LOG_DEBUG, "user=%s archivo=%s algo=%s digits=%d period=%d window=%d",
                   user, path, totp_algo_name(params.algo), params.digits,
                   params.period, params.window);

    /* estado del usuario */
    dropped = drop_privs(pamh, pw->pw_uid, pw->pw_gid, &ouid, &ogid);
    if (dropped < 0) return PAM_AUTHINFO_UNAVAIL;

    /* carga la config */
    terr = totp_load(path, pw->pw_uid, &cfg);

    if (dropped == 0) restore_privs(ouid, ogid);

    if (terr == TOTP_ERR_NOENT) { /* si no existe 2fa para este usuario */
        if (nullok) {
            pam_syslog(pamh, LOG_INFO, "%s sin 2FA; nullok activo", user);
            return PAM_IGNORE;
        }
        pam_syslog(pamh, LOG_NOTICE, "%s sin 2FA y sin nullok", user);
        return PAM_AUTH_ERR;
    }
    if (terr != TOTP_OK) {
        pam_syslog(pamh, LOG_ERR, "no se pudo leer %s: %s", path, totp_strerror(terr));
        return PAM_AUTHINFO_UNAVAIL;
    }

    /* pedir el codigo */
    if (ask_code(pamh, &code) != PAM_SUCCESS) {
        rc = PAM_CONV_ERR;
        goto out;
    }

    if (debug) pam_syslog(pamh, LOG_DEBUG, "codigo de %zu digitos", strlen(code));

    /* limite de intentos */
    now = time(NULL);
    need_save = 1;  /* guardamos el contador */

    if (totp_rate(&params, &cfg, now) == TOTP_ERR_RATE) {
        pam_syslog(pamh, LOG_NOTICE, "demasiados intentos para %s", user);
        rc = PAM_AUTH_ERR;
        goto out;
    }

    /* verificar */
    terr = totp_check_code(&params, &cfg, code, now, &matched);

    if (terr == TOTP_ERR_PERM) {
        /* el codigo era correcto pero ese ya se uso. */
        pam_syslog(pamh, LOG_NOTICE, "codigo ya utilizado para %s (anti-replay)", user);
        rc = PAM_AUTH_ERR;
        goto out;
    }

    /* chequeamos codigos de recuperacion */
    if (terr != TOTP_OK && totp_check_scratch(&cfg, code) == TOTP_OK) {
        terr = TOTP_OK;
        used_scratch = 1;
        pam_syslog(pamh, LOG_NOTICE, "%s uso un codigo de recuperacion; quedan %d", user, cfg.n_scratch);
    }

    if (terr != TOTP_OK) {
        pam_syslog(pamh, LOG_NOTICE, "codigo invalido para %s", user);
        rc = PAM_AUTH_ERR;
        goto out;
    }

    if (!used_scratch) cfg.last_counter = matched;

    pam_syslog(pamh, LOG_INFO, "segundo factor aceptado para %s", user);
    rc = PAM_SUCCESS;

out:
    /* se guarda en todos los caminos que llegaron a contar un intento, no
     * solo en el exitoso: si el contador no se persistiera, el limite se
     * reiniciaria en cada conexion nueva y no serviria de nada. */
    if (need_save) {
        int d2 = drop_privs(pamh, pw->pw_uid, pw->pw_gid, &ouid, &ogid);

        if (d2 >= 0) {
            totp_err_t werr = totp_save(path, &cfg);
            if (d2 == 0) restore_privs(ouid, ogid);
            if (werr != TOTP_OK) pam_syslog(pamh, LOG_WARNING, "no se pudo actualizar %s", path);
        }
    }

    if (code != NULL) {
        totp_wipe(code, strlen(code));
        free(code);
    }
    totp_wipe(&cfg, sizeof cfg);
    return rc;
}

/* obligatoria para completar el grupo auth. Este modulo no hace nada. */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void) pamh;
    (void) flags;
    (void) argc;
    (void) argv;
    return PAM_SUCCESS;
}
