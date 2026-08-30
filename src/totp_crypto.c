/* totp_crypto.c  Cifrado del seed
 *
 * El seed y los codigos de recuperacion se guardan cifrados con
 * AES-256-GCM. La clave se deriva de la contrasena del usuario con
 * PBKDF2-HMAC-SHA256, asi que solo quien la sepa puede descifrarlos (solo el usuario).
 * Los contadores (anti-replay y limite de intentos) quedan sin cifrar
 *
 * Se usa GCM y no CBC porque es cifrado autenticado: ademas de ocultar el
 * contenido genera una etiqueta que detecta cualquier modificacion. Si un
 * atacante cambia un byte del archivo, el descifrado falla en vez de devolver basura.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include "totp_common.h"

/* inicializa libgcrypt */
void totp_crypto_init(void) {
    static int hecho = 0;

    if (hecho) return;

    if (!gcry_check_version(GCRYPT_VERSION)) {
        /* no abortamos (el llamador va a recibir el error de la primera operacion y decide que hacer) */
        return;
    }
    /* memoria segura: gcrypt la bloquea para que no use el swap */
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    hecho = 1;
}

/* deriva la clave de cifrado a partir de la contrasenia,
 * PBKDF2 aplica HMAC-SHA256 TOTP_PBKDF2_ITER veces seguidas */
static totp_err_t derive_key(const char *pass, const unsigned char *salt, unsigned char *key) {
    gcry_error_t e;

    if (pass == NULL || *pass == '\0') return TOTP_ERR_PERM;

    e = gcry_kdf_derive(pass, strlen(pass), GCRY_KDF_PBKDF2, GCRY_MD_SHA256,
                        salt, TOTP_SALT_LEN, TOTP_PBKDF2_ITER, TOTP_KEY_LEN, key);

    return (e == 0) ? TOTP_OK : TOTP_ERR_CRYPTO;
}

/* struct de los parametros que se cifran */
struct claro {
    char secret[TOTP_SECRET_MAX];
    char scratch[TOTP_SCRATCH_N][TOTP_SCRATCH_LEN + 1];
    int n_scratch;
};

/* funcion de encriptado */
totp_err_t totp_encrypt(const char *pass, totp_cfg_t *cfg) {
    unsigned char key[TOTP_KEY_LEN];
    gcry_cipher_hd_t hd;
    struct claro p;
    gcry_error_t e;
    totp_err_t rc;
    size_t len;

    if (cfg == NULL) return TOTP_ERR_IO;
    if (sizeof p > sizeof cfg->blob) return TOTP_ERR_FORMAT;

    /* inicializamos */
    totp_crypto_init();

    /* sal y nonce nuevos en cada cifrado */
    gcry_create_nonce(cfg->salt, TOTP_SALT_LEN);
    gcry_create_nonce(cfg->nonce, TOTP_NONCE_LEN);

    /* obtiene clave */
    rc = derive_key(pass, cfg->salt, key);
    if (rc != TOTP_OK) return rc;

    /* copia el contenido a cifrar dentro del bloque */
    memset(&p, 0, sizeof p);
    snprintf(p.secret, sizeof p.secret, "%s", cfg->secret);
    memcpy(p.scratch, cfg->scratch, sizeof p.scratch);
    p.n_scratch = cfg->n_scratch;

    len = sizeof p;
    memcpy(cfg->blob, &p, len);
    totp_wipe(&p, sizeof p);

    e = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
    if (e == 0) e = gcry_cipher_setkey(hd, key, TOTP_KEY_LEN);
    if (e == 0) e = gcry_cipher_setiv(hd, cfg->nonce, TOTP_NONCE_LEN);
    if (e == 0) e = gcry_cipher_encrypt(hd, cfg->blob, len, NULL, 0);
    if (e == 0) e = gcry_cipher_gettag(hd, cfg->tag, TOTP_TAG_LEN);

    gcry_cipher_close(hd);
    totp_wipe(key, sizeof key);

    if (e != 0) {
        totp_wipe(cfg->blob, sizeof cfg->blob);
        return TOTP_ERR_CRYPTO;
    }

    cfg->bloblen = len;
    return TOTP_OK;
}

/* funcion de descifrado de la config */
totp_err_t totp_decrypt(const char *pass, totp_cfg_t *cfg) {
    unsigned char key[TOTP_KEY_LEN];
    unsigned char buf[TOTP_BLOB_MAX];
    gcry_cipher_hd_t hd;
    struct claro p;
    gcry_error_t e;
    totp_err_t rc;

    if (cfg == NULL || cfg->bloblen != sizeof p || cfg->bloblen > sizeof buf)
        return TOTP_ERR_FORMAT;

    /* inicializamos */
    totp_crypto_init();

    /* deriva la clave */
    rc = derive_key(pass, cfg->salt, key);
    if (rc != TOTP_OK) return rc;

    /* trabajamos sobre una copia entonces si el descifrado falla,
     * el bloque cifrado del archivo queda intatco en cfg */
    memcpy(buf, cfg->blob, cfg->bloblen);

    e = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
    if (e == 0) e = gcry_cipher_setkey(hd, key, TOTP_KEY_LEN);
    if (e == 0) e = gcry_cipher_setiv(hd, cfg->nonce, TOTP_NONCE_LEN);
    if (e == 0) e = gcry_cipher_decrypt(hd, buf, cfg->bloblen, NULL, 0);
    /* chequea la contrasenia y si el archivo fue manipulado */
    if (e == 0) e = gcry_cipher_checktag(hd, cfg->tag, TOTP_TAG_LEN);

    gcry_cipher_close(hd);
    totp_wipe(key, sizeof key);

    if (e != 0) {
        totp_wipe(buf, sizeof buf);
        return TOTP_ERR_PERM;
    }

    memcpy(&p, buf, sizeof p);
    p.secret[sizeof p.secret - 1] = '\0';

    if (p.n_scratch < 0 || p.n_scratch > TOTP_SCRATCH_N) {
        totp_wipe(&p, sizeof p);
        totp_wipe(buf, sizeof buf);
        return TOTP_ERR_FORMAT;
    }

    snprintf(cfg->secret, sizeof cfg->secret, "%s", p.secret);
    memcpy(cfg->scratch, p.scratch, sizeof cfg->scratch);
    cfg->n_scratch = p.n_scratch;

    totp_wipe(&p, sizeof p);
    totp_wipe(buf, sizeof buf);

    return TOTP_OK;
}
