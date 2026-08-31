/* totp_common.c  codigo compartido entre el modulo PAM y la herramienta. */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include "totp_common.h"

/* definicion de errores */
const char *totp_strerror(totp_err_t e) {
    switch (e) {
    case TOTP_OK: return "sin error";
    case TOTP_ERR_NOENT: return "el usuario no tiene 2FA configurado";
    case TOTP_ERR_PERM: return "permisos o propietario inseguros";
    case TOTP_ERR_IO: return "error de entrada/salida";
    case TOTP_ERR_FORMAT: return "archivo o codigo mal formado";
    case TOTP_ERR_CRYPTO: return "fallo la generacion del seed";
    case TOTP_ERR_RANGE: return "parametro fuera de rango";
    case TOTP_ERR_RATE: return "demasiados intentos, esperar";
    default: return "error desconocido";
    }
}

const char *totp_algo_name(int algo) {
    if (algo == COTP_SHA256) return "SHA256";
    if (algo == COTP_SHA512) return "SHA512";
    return "SHA1";
}

/* libera memoria */
void totp_wipe(void *p, size_t n) {
    if (p != NULL && n > 0) explicit_bzero(p, n);
}

/* Compara sin cortar en la primera diferencia. */
int totp_ct_equal(const char *a, const char *b, size_t n) {
    unsigned char diff = 0;
    size_t i;

    if (a == NULL || b == NULL)
        return 0;

    for (i = 0; i < n; i++)
        diff |= (unsigned char) a[i] ^ (unsigned char) b[i];

    return diff == 0;
}

int totp_path(char *out, size_t cap, const char *home) {
    int n;

    if (out == NULL || home == NULL) return -1;

    n = snprintf(out, cap, "%s/%s", home, TOTP_FILE);
    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* Parametros en /etc/totp.conf */

/* recorta espacios y saltos de linea */
static char *trim(char *s) {
    char *end;

    while (*s == ' ' || *s == '\t')
        s++;
    if (*s == '\0')
        return s;

    end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t'
                       || *end == '\r' || *end == '\n'))
        *end-- = '\0';

    return s;
}

totp_err_t totp_params_load(const char *path, totp_params_t *params) {
    int fd;
    FILE *fp;
    struct stat st;
    char line[TOTP_MAX_LINE];

    if (params == NULL) return TOTP_ERR_IO;

    /* valores por defecto */
    params->digits = TOTP_DEF_DIGITS;
    params->period = TOTP_DEF_PERIOD;
    params->window = TOTP_DEF_WINDOW;
    params->algo = TOTP_DEF_ALGO;
    params->rl_attempts = TOTP_DEF_RL_ATTEMPTS;
    params->rl_window = TOTP_DEF_RL_WINDOW;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        /* sin archivo se usan los valores predeterminados */
        return (errno == ENOENT) ? TOTP_OK : TOTP_ERR_IO;
    }

    if (fstat(fd, &st) != 0) {
        close(fd);
        return TOTP_ERR_IO;
    }

    /* chequeo la integridad de los permisos del archivo para que solo el root pueda cambiar los parametros */
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(fd);
        return TOTP_ERR_PERM;
    }

    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return TOTP_ERR_IO;
    }

    /* lee el archivo linea por linea */
    while (fgets(line, sizeof line, fp) != NULL) {
        char *hash, *eq, *key, *val;

        /* si es un comentario la saltea */
        if ((hash = strchr(line, '#')) != NULL) *hash = '\0';

        /* si no tiene '=' la saltea */
        eq = strchr(line, '=');
        if (eq == NULL) continue;

        *eq = '\0';
        key = trim(line); /* parametro */
        val = trim(eq + 1); /* valor */

        if (strcmp(key, "digits") == 0) params->digits = atoi(val);
        else if (strcmp(key, "period") == 0) params->period = atoi(val);
        else if (strcmp(key, "window") == 0) params->window = atoi(val);
        else if (strcmp(key, "rate_limit_attempts") == 0) params->rl_attempts = atoi(val);
        else if (strcmp(key, "rate_limit_window") == 0) params->rl_window = atoi(val);
        else if (strcmp(key, "algorithm") == 0) {
            if (strcasecmp(val, "SHA1") == 0) params->algo = COTP_SHA1;
            else if (strcasecmp(val, "SHA256") == 0) params->algo = COTP_SHA256;
            else if (strcasecmp(val, "SHA512") == 0) params->algo = COTP_SHA512;
            else {
                fclose(fp);
                return TOTP_ERR_RANGE;
            }
        }
        /* claves desconocidas se ignoran. */
    }
    fclose(fp);

    /* checque que los valores esten dentro del rango previsto */
    if (params->digits < MIN_DIGITS || params->digits > MAX_DIGITS
        || params->period < 1 || params->period > 300
        || params->window < 1 || params->window > 63
        || params->rl_attempts < 1 || params->rl_window < 1)
        return TOTP_ERR_RANGE;

    return TOTP_OK;
}

/* Estado del usuario en ~/.totp_auth
  Formato:
    " TOTP_ENC 1
    " SALT b7a66d56279915afbaf2a2d015599ff0    <- sal del KDF
    " NONCE 460e2d31aaec068dfe778b8a           <- nonce de GCM
    " TAG 22bb41f6c196296f15892ad2b07712ee     <- etiqueta de autenticación
    " DATA def1d536ea7e71473aeffce2390a0a...   <- seed + códigos de recuperacion (cifrados)
    " LAST_COUNTER 0                           <- anti-replay
    " RATE 0 0                                 <- rate-limiting (inicio de ventana e intentos)
*/

/* conversion hexadecimal */
/* el bloque cifrado son bytes crudos y el archivo es de texto */
static void bin2hex(const unsigned char *in, size_t n, char *out) {
    size_t i;
    for (i = 0; i < n; i++) sprintf(out + i * 2, "%02x", in[i]);
}

/* devuelve los bytes escritos, o 0 si no es hexadecimal valido */
static size_t hex2bin(const char *in, unsigned char *out, size_t cap) {
    size_t len = strlen(in), i;
    if (len == 0 || len % 2 != 0 || len / 2 > cap) return 0;
    for (i = 0; i < len / 2; i++)
        if (sscanf(in + i * 2, "%2hhx", &out[i]) != 1) return 0;

    return len / 2;
}

totp_err_t totp_load(const char *path, uid_t owner, const char *pass, totp_cfg_t *cfg) {
    int fd;
    FILE *fp;
    struct stat st;
    char line[TOTP_MAX_LINE];
    int tiene_data = 0;

    if (path == NULL || cfg == NULL) return TOTP_ERR_IO;

    memset(cfg, 0, sizeof *cfg);

    /* O_NOFOLLOW: el archivo esta en el home del usuario, asi que podria
     * reemplazarlo por un enlace al archivo de otra persona. */
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return (errno == ENOENT) ? TOTP_ERR_NOENT : TOTP_ERR_IO;

    if (fstat(fd, &st) != 0) {
        close(fd);
        return TOTP_ERR_IO;
    }

    /* chequeo la integridad de los permisos del archivo */
    if (!S_ISREG(st.st_mode)  /* archivo regular */
        || st.st_uid != owner /* del usuario */
        || (st.st_mode & (S_IRWXG | S_IRWXO)) != 0) /* solo el dueño */
    {
        close(fd);
        return TOTP_ERR_PERM;
    }

    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return TOTP_ERR_IO;
    }

    /* lee el archivo linea por linea */
    while (fgets(line, sizeof line, fp) != NULL) {
        char *nl;
        if ((nl = strpbrk(line, "\r\n")) != NULL) *nl = '\0';

        if (strncmp(line, "\" SALT ", 7) == 0) {
            if (hex2bin(line + 7, cfg->salt, TOTP_SALT_LEN) != TOTP_SALT_LEN) {
                fclose(fp);
                return TOTP_ERR_FORMAT;
            }
        } else if (strncmp(line, "\" NONCE ", 8) == 0) {
            if (hex2bin(line + 8, cfg->nonce, TOTP_NONCE_LEN) != TOTP_NONCE_LEN) {
                fclose(fp);
                return TOTP_ERR_FORMAT;
            }
        } else if (strncmp(line, "\" TAG ", 6) == 0) {
            if (hex2bin(line + 6, cfg->tag, TOTP_TAG_LEN) != TOTP_TAG_LEN) {
                fclose(fp);
                return TOTP_ERR_FORMAT;
            }
        } else if (strncmp(line, "\" DATA ", 7) == 0) {
            cfg->bloblen = hex2bin(line + 7, cfg->blob, sizeof cfg->blob);
            if (cfg->bloblen == 0) {
                fclose(fp);
                return TOTP_ERR_FORMAT;
            }
            tiene_data = 1;
        } else if (strncmp(line, "\" LAST_COUNTER ", 15) == 0) {
            cfg->last_counter = strtoll(line + 15, NULL, 10);
        } else if (strncmp(line, "\" RATE ", 7) == 0) {
            long long t = 0;
            int n = 0;
            if (sscanf(line + 7, "%lld %d", &t, &n) == 2) {
                cfg->rate_start = (time_t) t;
                cfg->rate_count = n;
            }
        }
        /* cualquier otra linea se ignora */
    }
    fclose(fp);

    if (!tiene_data) return TOTP_ERR_FORMAT;

    /* Descifrar, devuelve TOTP_ERR_PERM si la contrasenia no es la correcta o si alguien altero el archivo */
    return totp_decrypt(pass, cfg);
    fclose(fp);

    if (!tiene_data || !is_string_valid_b32(cfg->secret)) {
        totp_wipe(cfg, sizeof *cfg);
        return TOTP_ERR_FORMAT;
    }

    return TOTP_OK;
}

/* guarda la configuracion de cfg en el archivo
 *
 * Con pass != NULL vuelve a cifrar el bloque (necesario para generar el
 * seed y tmb cuando se usa un codigo de recuperacion).
 * Con pass == NULL conserva el bloque y solo actualiza los contadores
 * Asi no se genera un nonce nuevo en cada intento */
totp_err_t totp_save(const char *path, const char *pass, const totp_cfg_t *cfg) {
    totp_cfg_t tmp;
    const totp_cfg_t *w = cfg;
    char hex[TOTP_BLOB_MAX * 2 + 1];
    int fd;
    FILE *fp;
    totp_err_t rc = TOTP_OK;

    if (path == NULL || cfg == NULL) return TOTP_ERR_IO;

    if (pass != NULL) {
        memcpy(&tmp, cfg, sizeof tmp);
        rc = totp_encrypt(pass, &tmp);
        if (rc != TOTP_OK) {
            totp_wipe(&tmp, sizeof tmp);
            return rc;
        }
        w = &tmp;
    } else if (cfg->bloblen == 0) {
        return TOTP_ERR_FORMAT;   /* nada cifrado que conservar */
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        rc = TOTP_ERR_IO;
        goto fin;
    }

    /* si el archivo ya existia 'open()' no cambia su modo, y al crearlo el
     * umask puede haberlo aflojado, lo forzamos a 0600 */
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        close(fd);
        rc = TOTP_ERR_IO;
        goto fin;
    }

    fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        rc = TOTP_ERR_IO;
        goto fin;
    }

    /* escribimos los parametros */
    fprintf(fp, "\" TOTP_ENC 1\n");
    bin2hex(w->salt, TOTP_SALT_LEN, hex);
    fprintf(fp, "\" SALT %s\n", hex);
    bin2hex(w->nonce, TOTP_NONCE_LEN, hex);
    fprintf(fp, "\" NONCE %s\n", hex);
    bin2hex(w->tag, TOTP_TAG_LEN, hex);
    fprintf(fp, "\" TAG %s\n", hex);
    bin2hex(w->blob, w->bloblen, hex);
    fprintf(fp, "\" DATA %s\n", hex);
    fprintf(fp, "\" LAST_COUNTER %lld\n", (long long) cfg->last_counter);
    fprintf(fp, "\" RATE %lld %d\n", (long long) cfg->rate_start, cfg->rate_count);

    if (fclose(fp) != 0) rc = TOTP_ERR_IO;

fin:  /* borra 'tmp' que contiene el seed sin cifrar */
    if (pass != NULL) totp_wipe(&tmp, sizeof tmp);
    return rc;
}

/* Generacion de la seed */

/* genera la seed y la escribe */
totp_err_t totp_generate(totp_cfg_t *cfg) {
    unsigned char raw[TOTP_SEED_BYTES];
    cotp_error_t cerr = NO_ERROR;
    char *b32;
    int i;

    if (cfg == NULL) return TOTP_ERR_IO;

    memset(cfg, 0, sizeof *cfg);

    if (getentropy(raw, sizeof raw) != 0) return TOTP_ERR_CRYPTO;

    b32 = base32_encode(raw, sizeof raw, &cerr);
    totp_wipe(raw, sizeof raw);

    if (b32 == NULL || cerr != NO_ERROR || strlen(b32) >= sizeof cfg->secret) {
        free(b32);
        return TOTP_ERR_CRYPTO;
    }

    strcpy(cfg->secret, b32);
    totp_wipe(b32, strlen(b32));
    free(b32);

    /* codigos de recuperacion de 8 digitos. */
    for (i = 0; i < TOTP_SCRATCH_N; i++) {
        uint32_t v;

        if (getentropy((unsigned char *) &v, sizeof v) != 0) {
            totp_wipe(cfg, sizeof *cfg);
            return TOTP_ERR_CRYPTO;
        }
        snprintf(cfg->scratch[i], sizeof cfg->scratch[i], "%08u", 10000000u + (v % 90000000u));
    }
    cfg->n_scratch = TOTP_SCRATCH_N;

    /* last_counter = 0 significa "ningun codigo usado todavia". No lo
     * arrancamos en el paso actual: eso rechazaria el primer codigo durante 30 s */
    cfg->last_counter = 0;

    return TOTP_OK;
}

/* Verificacion */

/* cheque si el codigo recibido es correcto */
totp_err_t totp_check_code(const totp_params_t *params, const totp_cfg_t *cfg,
                           const char *code, time_t now, int64_t *matched) {
    int64_t now_counter, found_counter = 0;
    int i, found = 0;

    if (params == NULL || cfg == NULL || code == NULL) return TOTP_ERR_IO;

    /* validar el largo antes de comparar */
    if (strlen(code) != (size_t) params->digits) return TOTP_ERR_FORMAT;

    /* el contador TOTP es la cantidad de periodos transcurridos desde epoch */
    now_counter = (int64_t) now / params->period;

    /* window es el total de codigos aceptados, centrado: con 3, i va de -1 a 1 */
    for (i = -((params->window - 1) / 2); i <= params->window / 2; i++) {
        int64_t c = now_counter + i;
        cotp_error_t cerr = NO_ERROR;
        char *expected;

        if (c < 0) continue;

        /* correcmos el algoritmo con los parametros indicados */
        expected = get_totp_at(cfg->secret, (long) (c * params->period),
                               params->digits, params->period, params->algo, &cerr);
        if (expected == NULL || cerr != NO_ERROR) {
            free(expected);
            continue;
        }

        /* sin break aunque ya haya coincidencia: cortar antes delataria
         * por tiempo en que parte de la ventana cayo el codigo. */
        if (totp_ct_equal(expected, code, (size_t) params->digits) && !found) {
            found = 1;
            found_counter = c;
        }

        totp_wipe(expected, strlen(expected));
        free(expected);
    }

    if (!found) return TOTP_ERR_FORMAT;

    /* anti-replay exigido por la RFC */
    if (found_counter <= cfg->last_counter) return TOTP_ERR_PERM;

    if (matched != NULL) *matched = found_counter;

    return TOTP_OK;
}

/* chequea si es un codigo de recuperacion */
totp_err_t totp_check_scratch(totp_cfg_t *cfg, const char *code) {
    int i, hit = -1;

    if (cfg == NULL || code == NULL || strlen(code) != TOTP_SCRATCH_LEN)
        return TOTP_ERR_FORMAT;

    for (i = 0; i < cfg->n_scratch; i++) {
        if (totp_ct_equal(cfg->scratch[i], code, TOTP_SCRATCH_LEN) && hit < 0)
            hit = i;
    }

    if (hit < 0) return TOTP_ERR_FORMAT;

    /* de un solo uso: se elimina corriendo el resto de la lista */
    for (i = hit; i < cfg->n_scratch - 1; i++)
        strcpy(cfg->scratch[i], cfg->scratch[i + 1]);
    cfg->n_scratch--;

    return TOTP_OK;
}

/* limite de intentos */

/* Cuenta los intentos dentro de una ventana de rl_window segundos.
 * Cuando la ventana vence, el contador arranca de cero.
 *
 * Devuelve TOTP_ERR_RATE si este intento se pasa del limite. */
totp_err_t totp_rate(const totp_params_t *params, totp_cfg_t *cfg, time_t now) {
    if (params == NULL || cfg == NULL) return TOTP_OK;

    /* la ventana se reinicia solo despues de rl_window segundos SIN
     * intentos. Si el usuario sigue probando, el contador sigue vivo. */
    if (now < cfg->rate_start || now - cfg->rate_start >= params->rl_window) 
        cfg->rate_count = 0;

    /* poniendo esa linea fuera del if aseguramos que la ventana se reinicia luego de cada intento */
    cfg->rate_start = now;
    cfg->rate_count++;

    return (cfg->rate_count > params->rl_attempts) ? TOTP_ERR_RATE : TOTP_OK;
}
