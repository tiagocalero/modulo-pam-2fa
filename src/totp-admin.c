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
#include <termios.h>
#include "totp_common.h"

#define ISSUER "Lab1_TSI-G08"

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

    /* contrasena para cifrar el seed
     * Tiene que ser la misma con la que el usuario entra al sistema
     * La pedimos dos veces para asegurarse de que el usuario la escriba bien */
    p = getpass("Contrasena de tu cuenta (para cifrar el seed): ");
    if (p == NULL || *p == '\0') {
        fprintf(stderr, "error: contrasena vacia\n");
        return 1;
    }
    snprintf(pass, sizeof pass, "%s", p);
    totp_wipe(p, strlen(p));

    p = getpass("Repetila: ");
    if (p == NULL || strcmp(pass, p) != 0) {
        fprintf(stderr, "error: las contrasenas no coinciden\n");
        if (p != NULL) totp_wipe(p, strlen(p));
        totp_wipe(pass, sizeof pass);
        return 1;
    }
    totp_wipe(p, strlen(p));

    /* generamos seed */
    e = totp_generate(&cfg);
    if (e != TOTP_OK) {
        fprintf(stderr, "error: %s\n", totp_strerror(e));
        totp_wipe(pass, sizeof pass);
        return 1;
    }

    /* guardamos en el archivo del usuario */
    e = totp_save(path, &cfg);
    totp_wipe(pass, sizeof pass);
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
