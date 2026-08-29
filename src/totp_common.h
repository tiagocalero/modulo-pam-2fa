/* totp_common.h  definiciones compartidas entre pam_totp.so y totp-admin. */

#ifndef TOTP_COMMON_H
#define TOTP_COMMON_H

#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>
#include <time.h>
#include <cotp.h>

/* definiciones para compatibilidad entre versiones de libotp */
#ifndef COTP_SHA1
#define COTP_SHA1 SHA1
#define COTP_SHA256 SHA256
#define COTP_SHA512 SHA512
#endif
#ifndef MIN_DIGITS
#define MIN_DIGITS MIN_DIGTS
#endif

#define TOTP_CONF "/etc/totp.conf"
#define TOTP_FILE ".totp_auth"

/* valores por defecto del algoritmo */
#define TOTP_DEF_DIGITS 6
#define TOTP_DEF_PERIOD 30
#define TOTP_DEF_WINDOW 3
#define TOTP_DEF_ALGO COTP_SHA1
#define TOTP_DEF_RL_ATTEMPTS 3
#define TOTP_DEF_RL_WINDOW 30

#define TOTP_SEED_BYTES 20  /* 160 bits */
#define TOTP_SECRET_MAX 64
#define TOTP_SCRATCH_N 5
#define TOTP_SCRATCH_LEN 8
#define TOTP_MAX_LINE 256

typedef enum {
    TOTP_OK = 0,
    TOTP_ERR_NOENT,
    TOTP_ERR_PERM,
    TOTP_ERR_IO,
    TOTP_ERR_FORMAT,
    TOTP_ERR_CRYPTO,
    TOTP_ERR_RANGE,
    TOTP_ERR_RATE
} totp_err_t;

const char *totp_strerror(totp_err_t e);
const char *totp_algo_name(int algo);

/* parametros del algoritmo en /etc/totp.conf */
typedef struct {
    int digits;  /* digitos por codigo */
    int period;  /* duracion de cada codigo */
    int window;  /* tamanio de ventana */
    int algo;  /* algoritmo usado */
    int rl_attempts;  /* cantidad de intentos */
    int rl_window;  /* periodo de bloqueo */
} totp_params_t;

/* pone en /etc/totp.conf los valores por defecto
 *
 * Si el archivo no existe -> TOTP_OK con los defaults.
 * Si existe pero no es de root o lo puede escribir otro -> TOTP_ERR_PERM
 */
totp_err_t totp_params_load(const char *path, totp_params_t *params);

/* estado del usuario en ~/.totp_auth */
typedef struct {
    char secret[TOTP_SECRET_MAX]; /* seed en Base32 */
    int64_t last_counter; /* anti-replay */
    time_t rate_start;  /* inicio de la ventana de intentos */
    int rate_count; /* intentos contados en la ventana */
    char scratch[TOTP_SCRATCH_N][TOTP_SCRATCH_LEN + 1];
    int n_scratch;
} totp_cfg_t;

/* arma <home>/.totp_auth en out. Devuelve 0 si entro, -1 si no. */
int totp_path(char *out, size_t cap, const char *home);

totp_err_t totp_load(const char *path, uid_t owner, totp_cfg_t *cfg);
totp_err_t totp_save(const char *path, const totp_cfg_t *cfg);
totp_err_t totp_generate(totp_cfg_t *cfg);

totp_err_t totp_check_code(const totp_params_t *params, const totp_cfg_t *cfg,
                           const char *code, time_t now, int64_t *matched);
totp_err_t totp_check_scratch(totp_cfg_t *cfg, const char *code);

/* Registra un intento y dice si se paso del limite. */
totp_err_t totp_rate(const totp_params_t *params, totp_cfg_t *cfg, time_t now);

int totp_ct_equal(const char *a, const char *b, size_t n);
void totp_wipe(void *p, size_t n);

#endif /* TOTP_COMMON_H */
