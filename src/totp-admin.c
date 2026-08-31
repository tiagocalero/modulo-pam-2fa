/* totp-admin.c  Genera el seed TOTP del usuario que lo ejecuta.
 *
 * Cada usuario corre 'totp-admin' en su propia sesion y queda dado de alta.
 * Para dar de baja a alguien, el administrador borra su archivo ~/.totp_auth
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <limits.h>
#include <sys/wait.h>
#include <security/pam_appl.h>
#include "totp_common.h"

#define ISSUER "Lab1_TSI-G08"

/* funcion de conversacion para PAM
 * PAM va a pedir la contrasena; en vez de preguntarle otra vez al usuario,
 * le devolvemos la que ya ingreso, pasada por appdata_ptr. */
static int conv_pass(int n, const struct pam_message **msg, struct pam_response **resp, void *appdata) {
    struct pam_response *r = calloc((size_t) n, sizeof *r);
    int i;
    if (r == NULL) return PAM_BUF_ERR;

    for (i = 0; i < n; i++)
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF)
            r[i].resp = strdup((const char *) appdata);

    *resp = r;
    return PAM_SUCCESS;
}

/* verifica que 'pass' sea realmente la contrasena de 'user'.
 *
 * No lee /etc/shadow, se lo pedimos a PAM, que para eso delega en /usr/sbin/unix_chkpwd.
 * Devuelve 0 si la contrasena es correcta, -1 si no. */
static int check_pass(const char *user, const char *pass) {
    struct pam_conv conv = { conv_pass, (void *) pass };
    pam_handle_t *h = NULL;
    int rc;

    if (pam_start("totp-admin", user, &conv, &h) != PAM_SUCCESS) return -1;

    rc = pam_authenticate(h, PAM_DISALLOW_NULL_AUTHTOK);
    pam_end(h, rc);

    return (rc == PAM_SUCCESS) ? 0 : -1;
}

/* dibuja el QR invocando qrencode(). */
static int draw_qr(const char *uri) {
    pid_t pid = fork();
    int status;

    if (pid < 0) return -1;

    if (pid == 0) {
        execlp("qrencode", "qrencode", "-t", "ANSIUTF8", "-o", "-", uri, (char *) NULL);
        _exit(127);   /* execlp solo retorna si fallo */
    }
    if (waitpid(pid, &status, 0) < 0) return -1;

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

int main(void) {
    totp_params_t params;
    totp_cfg_t cfg;
    struct passwd *pw;
    char path[PATH_MAX];
    char uri[512];
    char pass[256];
    char *p;
    totp_err_t e;
    int i;

    /* leemos los parametros para poner los valores correctos en el QR */
    e = totp_params_load(TOTP_CONF, &params);
    if (e != TOTP_OK) {
        fprintf(stderr, "error: parametros invalidos en %s: %s\n", TOTP_CONF, totp_strerror(e));
        return 1;
    }

    /* obtenemos la cuenta del usuario */
    pw = getpwuid(getuid());
    if (pw == NULL) {
        fprintf(stderr, "error: no se pudo resolver el usuario\n");
        return 1;
    }

    if (totp_path(path, sizeof path, pw->pw_dir) != 0) {
        fprintf(stderr, "error: ruta demasiado larga\n");
        return 1;
    }

    /* regenerar deja al usuario afuera hasta que reconfigure la app, asi
     * que pedimos confirmacion si ya habia una seed. */
    if (access(path, F_OK) == 0) {
        char resp[16];

        printf("Ya existe %s\n"
               "Si continuas, el token actual dejara de funcionar.\n"
               "Sobrescribir? [s/N] ", path);
        fflush(stdout);

        if (fgets(resp, sizeof resp, stdin) == NULL || (resp[0] != 's' && resp[0] != 'S')) {
            printf("Cancelado.\n");
            return 1;
        }
    }

    p = getpass("Contrasena de tu cuenta (para cifrar el seed): ");
    if (p == NULL || *p == '\0') {
        fprintf(stderr, "error: contrasena vacia\n");
        return 1;
    }
    snprintf(pass, sizeof pass, "%s", p);
    totp_wipe(p, strlen(p));

    /* verificamos antes de generar */
    if (check_pass(pw->pw_name, pass) != 0) {
        fprintf(stderr, "error: la contrasena no es correcta\n");
        totp_wipe(pass, sizeof pass);
        return 1;
    }

    /* generamos seed */
    e = totp_generate(&cfg);
    if (e != TOTP_OK) {
        fprintf(stderr, "error: %s\n", totp_strerror(e));
        totp_wipe(pass, sizeof pass);
        return 1;
    }

    /* guardamos en el archivo del usuario */
    e = totp_save(path, pass, &cfg);
    if (e != TOTP_OK) {
        fprintf(stderr, "error: no se pudo escribir %s: %s\n", path, strerror(errno));
        totp_wipe(&cfg, sizeof cfg);
        return 1;
    }

    /* generamos e imprimimos el QR */
    snprintf(uri, sizeof uri,
             "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
             ISSUER, pw->pw_name, cfg.secret, ISSUER, totp_algo_name(params.algo), params.digits, params.period);

    printf("\n2FA generado para '%s' en %s\n\n", pw->pw_name, path);

    if (draw_qr(uri) != 0)
        fprintf(stderr, "(qrencode no esta instalado)\n\n");

    /* mostramos la seed en texto por las dudas */
    printf("URI: %s\n", uri);
    printf("Seed: %s\n", cfg.secret);
    printf("Parametros: %s, %d digitos, periodo %d s\n\n",
           totp_algo_name(params.algo), params.digits, params.period);

    if (params.algo != COTP_SHA1 || params.digits != 6 || params.period != 30)
        printf("AVISO: se estan usando unos parametros distintos a los predeterminados SHA1/6/30\n\n");

    printf("Codigos de recuperacion (un solo uso cada uno):\n");
    for (i = 0; i < cfg.n_scratch; i++) printf("%s\n", cfg.scratch[i]);

    totp_wipe(&cfg, sizeof cfg);
    return 0;
}
