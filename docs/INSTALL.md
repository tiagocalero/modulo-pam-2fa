# pam_totp — Guía de instalación

Módulo PAM de segundo factor TOTP (RFC 6238) sobre **libcotp**, con
herramienta de gestión e integración con OpenSSH.

Probado en Ubuntu 24.04. Las instrucciones cubren también Fedora/RHEL y
Arch, que difieren en varios puntos importantes.

---

> ## ⚠️ Antes de empezar
>
> Una configuración incorrecta de PAM puede dejarte **sin acceso a la
> máquina**.
>
> 1. Tomá una **snapshot** si estas en una VM.
> 2. Dejá una **sesión root abierta en otra terminal** y no la cierres
>    hasta haber verificado que podés entrar.
> 3. Tené a mano la **consola gráfica** de la VM.
>
> Si te bloqueás, mirá la sección [7. Recuperación](#7-recuperación).

---

## 1. Cómo está organizado

Dos archivos con dueños distintos:

| Archivo | Dueño | Contiene | Lo cambia |
|---|---|---|---|
| `/etc/totp.conf` | `root:root 0644` | dígitos, período, ventana, algoritmo, límite de intentos | solo root |
| `~/.totp_auth` | `usuario:usuario 0600` | seed, contador anti-replay, intentos, códigos de recuperación | el usuario |

Esa separación es el punto del diseño: si los parámetros vivieran en el
archivo del usuario, el usuario podría aflojar la política de seguridad
del servidor por su cuenta.

**El módulo verifica `/etc/totp.conf` en cada login.** Si no pertenece a
root o es escribible por grupo u otros, **deniega el acceso** en lugar de
seguir con los valores por defecto. Si el archivo no existe, usa los
defaults: es una instalación válida.

Como el estado está en el home, hay **auto-servicio**: cada usuario se da
de alta solo, sin molestar al administrador.

> ### El agujero de `nullok` + auto-servicio
>
> Como el archivo es del usuario, el usuario puede borrarlo. Con `nullok`
> activo, `rm ~/.totp_auth` **desactiva el segundo factor de esa cuenta**.
>
> La salida es **quitar `nullok`** cuando termine la migración: a partir de
> ahí, quien borre su archivo se queda afuera y necesita al administrador.

### Parámetros

| Clave en `totp.conf` | Default | Nota |
|---|---|---|
| `algorithm` | SHA1 | Las apps ignoran este parámetro del QR y usan SHA1 igual |
| `digits` | 6 | Las apps ignoran `digits`; con otro valor generan códigos que no validan |
| `period` | 30 | RFC 6238 §5.2 |
| `window` | 3 | Cantidad **total** de códigos, centrada. 3 = ±1 paso ≈ 90 s |
| `rate_limit_attempts` | 3 | Por usuario; persiste entre reconexiones, a diferencia de `MaxAuthTries` |
| `rate_limit_window` | 30 | Segundos |

> **Cuidado con `digits` y `algorithm`.** Google Authenticator ignora ambos
> y usa siempre SHA1 con 6 dígitos. Si los cambiás, esa app genera códigos
> que **nunca** validan, y sin dar error. La herramienta avisa cuando la
> política se aparta de SHA1/6/30.

---

## 2. Dependencias

### Debian / Ubuntu

```bash
sudo apt update
sudo apt install build-essential libcotp-dev libpam0g-dev qrencode
```

### Fedora / RHEL

**`libcotp` no está empaquetada en Fedora**, hay que compilarla:

```bash
sudo dnf install gcc make cmake pam-devel libgcrypt-devel qrencode git

git clone https://github.com/paolostivanin/libcotp.git
cd libcotp && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make && sudo make install
sudo ldconfig
cd ../..
```

### Arch

`libcotp` está en el AUR:

```bash
sudo pacman -S base-devel qrencode
yay -S libcotp        # o el helper de AUR que uses
```

### Sincronización horaria — no es opcional

TOTP deriva el código de la hora. Si el reloj se desfasa más allá de la
ventana, **ningún usuario puede entrar**:

```bash
timedatectl status              # "System clock synchronized: yes"
sudo timedatectl set-ntp true
```

En VirtualBox instalá las *Guest Additions*: el reloj de la VM se corre
notoriamente después de suspender el host.

---

## 3. Compilación e instalación

El proyecto son cuatro archivos de código:

```
src/totp_common.h   definiciones compartidas
src/totp_common.c   lectura/escritura de archivos, generación y verificación
src/pam_totp.c      el módulo PAM
src/totp-admin.c    la herramienta que genera el seed
```

`totp_common.c` se compila dentro de los dos ejecutables, así el módulo y
la herramienta no pueden divergir en cómo leen y escriben los archivos.


```bash
cd totp
make
sudo make install
```

| Qué | Dónde |
|---|---|
| `pam_totp.so` | directorio de módulos PAM (detectado automáticamente) |
| `totp-admin` | `/usr/local/bin/` |
| `totp.conf` | `/etc/totp.conf` (no se pisa si ya existe) |

El Makefile busca el directorio de módulos PAM probando dónde vive
`pam_permit.so`, porque cambia según la distribución:

| Distribución | Directorio |
|---|---|
| Debian / Ubuntu | `/usr/lib/x86_64-linux-gnu/security` |
| Fedora / RHEL | `/usr/lib64/security` |
| Arch / openSUSE | `/usr/lib/security` |

Si por algún motivo elige mal:

```bash
sudo make install SECURITYDIR=/usr/lib64/security
```

Comprobá que el módulo quedó bien:

```bash
nm -D --defined-only $(dirname $(find / -name pam_permit.so 2>/dev/null | head -1))/pam_totp.so | grep pam_sm
# T pam_sm_authenticate
# T pam_sm_setcred
```

### Fedora / RHEL: SELinux

Con SELinux en *enforcing*, un módulo PAM sin el contexto correcto **no
carga**, y el login falla sin un mensaje que apunte a la causa. El
`make install` corre `restorecon` automáticamente si está disponible.

Si aun así falla, revisá las denegaciones:

```bash
sudo ausearch -m avc -ts recent
```

Para confirmar que el problema es SELinux y no tu código, podés ponerlo en
permisivo **temporalmente** durante el diagnóstico:

```bash
sudo setenforce 0        # diagnóstico solamente
sudo setenforce 1        # volver a activarlo
```

Si el módulo anda con `setenforce 0` y falla con `1`, es contexto de
SELinux. Anotalo en el informe: es un problema real de despliegue que no
aparece en Debian.

---

## 4. Alta de usuarios

**Hacé esto ANTES de tocar PAM.** Si activás el módulo sin `nullok` y nadie
tiene seed, nadie puede entrar.

Cada usuario, en su propia sesión, sin privilegios:

```bash
totp-admin
```

Muestra el QR, la URI `otpauth://`, el seed en Base32 y cinco **códigos de
recuperación** de un solo uso. El archivo queda en `~/.totp_auth` con modo
`0600`.

Verificá en el acto, antes de que el usuario se vaya, que el código que
muestra su teléfono es el correcto:

```bash
oathtool --totp -b "$(head -1 ~/.totp_auth)"
```

> **Sobre el canal de entrega.** Quien vea el QR *es* el segundo factor,
> para siempre y sin dejar rastro. Enrolar por SSH con solo contraseña
> significa que quien tenga esa contraseña puede enrolar *su* dispositivo.
> Preferí hacerlo presencialmente y que la ventana con `nullok` sea corta.

### Cómo funciona la herramienta

`totp-admin` no toma argumentos: genera el seed del usuario que la ejecuta
y nada más. Si ya existía un seed, pide confirmación antes de pisarlo.

Para **dar de baja** a alguien, el administrador borra su archivo:

```bash
sudo rm /home/tiago/.totp_auth
```

Para **diagnosticar** un código, usá `oathtool` (ver sección 9).
Con `--user` sobre otra cuenta, todas requieren root.

---

## 5. Configuración de PAM

Editá `/etc/pam.d/sshd`. **La línea de referencia cambia según la
distribución.**

### Debian / Ubuntu

Buscá `@include common-auth` y agregá **debajo**:

```
auth    required    pam_totp.so nullok debug
```

### Fedora / RHEL

Buscá `auth substack password-auth` y agregá **debajo**:

```
auth    required    pam_totp.so nullok debug
```

### Arch

Buscá `auth include system-remote-login` y agregá **debajo** la misma línea.

### Qué significa cada parte

**El orden importa.** Como la autenticación por contraseña va primero, se
pide la contraseña y *después* el código.

**`nullok`** hace que el módulo se abstenga (`PAM_IGNORE`) si el usuario no
tiene `~/.totp_auth`. Imprescindible durante el despliegue; **quitalo**
cuando todos estén dados de alta.

**`debug`** registra el flujo en syslog. Sacalo en producción.

Opciones disponibles: `debug`, `nullok`, `no_scratch`, `conf=RUTA`.

---

## 6. Configuración de sshd

```bash
sudo nano /etc/ssh/sshd_config.d/99-totp.conf
```

```
UsePAM yes
KbdInteractiveAuthentication yes
PasswordAuthentication no
```

- **`KbdInteractiveAuthentication yes`** habilita el diálogo por el que
  viaja el pedido del código. Sin esto, PAM nunca llega a preguntar nada.
  En OpenSSH viejo (< 8.7) la directiva se llama
  `ChallengeResponseAuthentication`.
- **`PasswordAuthentication no`** deshabilita el método `password` nativo.
  Por ese camino sshd le entrega a PAM una sola cadena y la responde a
  *todos* los prompts, con lo cual el pedido del código recibe la
  contraseña y siempre falla.

Si tu versión no soporta el directorio `sshd_config.d/`, poné esas líneas
directamente en `/etc/ssh/sshd_config`.

Validá y reiniciá — **el nombre del servicio cambia según la distro**:

```bash
sudo sshd -t

sudo systemctl restart ssh      # Debian / Ubuntu
sudo systemctl restart sshd     # Fedora / RHEL / Arch
```

---

## 7. Verificación

Desde otra terminal, **sin cerrar la actual**:

```bash
ssh tiago@192.168.68.58
```

Esperado:

```
(tiago@192.168.68.58) Password:
(tiago@192.168.68.58) Codigo de verificacion:
```

Con el log en paralelo:

```bash
sudo journalctl -u ssh -f       # o -u sshd en Fedora/Arch
```

Con `debug` activo:

```
sshd(pam_totp)[1234]: parametros: algo=SHA1 digits=6 period=30 window=3 rate=3/30s
sshd(pam_totp)[1234]: usuario=tiago archivo=/home/tiago/.totp_auth nullok=1
sshd(pam_totp)[1234]: codigo recibido: 6 digitos
sshd(pam_totp)[1234]: segundo factor aceptado para tiago
```

### Qué probar

- [ ] Código correcto → entra
- [ ] Código incorrecto → `codigo TOTP invalido`
- [ ] **Mismo código dos veces** → `ya utilizado (anti-replay)`
- [ ] Código de recuperación → entra, y `quedan 4`
- [ ] El mismo código de recuperación otra vez → rechazado
- [ ] `chmod 644 ~/.totp_auth` → `permisos o propietario inseguros`
- [ ] `sudo chmod 666 /etc/totp.conf` → **denegado**
- [ ] Enlace simbólico de `~/.totp_auth` a un archivo ajeno → denegado
- [ ] 4 códigos incorrectos seguidos → `demasiados intentos`
- [ ] Estando limitado, el código **correcto** también falla
- [ ] A los 30 s vuelve a funcionar
- [ ] Usuario sin seed y `nullok` → entra solo con contraseña
- [ ] Usuario sin seed y **sin** `nullok` → denegado

Restaurá los permisos después:

```bash
chmod 600 ~/.totp_auth
sudo chmod 644 /etc/totp.conf
```

---

## 8. Recuperación

**SSH roto, con acceso a la consola:**

```bash
sudo sed -i '/pam_totp.so/d' /etc/pam.d/sshd
sudo systemctl restart ssh      # o sshd
```

**Los parámetros quedaron mal y nadie entra.** El módulo deniega si
`/etc/totp.conf` es inválido o inseguro:

```bash
sudo chown root:root /etc/totp.conf && sudo chmod 644 /etc/totp.conf
# o sacarlo: sin archivo se usan los defaults
sudo mv /etc/totp.conf /etc/totp.conf.bak
```

**El usuario perdió el teléfono.** Que use un código de recuperación. Si no
le quedan:

```bash
sudo rm /home/tiago/.totp_auth      # y que vuelva a correr totp-admin
```

**Sin acceso de ninguna forma.** Modo *recovery* desde GRUB
(*Advanced options* → *recovery mode* → *root shell*):

```bash
mount -o remount,rw /
sed -i '/pam_totp.so/d' /etc/pam.d/sshd
reboot
```

---

## 9. Diagnóstico

| Síntoma | Causa probable | Solución |
|---|---|---|
| No aparece el prompt del código | `KbdInteractiveAuthentication` en `no`, o falta la línea en `/etc/pam.d/sshd` | revisar el drop-in de sshd |
| `PAM unable to dlopen(...)` | el `.so` no está en el directorio correcto | `sudo make install SECURITYDIR=...` |
| Todo falla en Fedora sin mensaje claro | contexto SELinux del módulo | `sudo restorecon -F .../pam_totp.so`; ver `ausearch -m avc -ts recent` |
| `error: unknown type name 'size_t'` al compilar | el header de libcotp usa `size_t` sin incluir `<stddef.h>` | ya está resuelto en el código: `<stddef.h>` va antes de `<cotp.h>` |
| `SHA1 undeclared` al compilar | libcotp v4 renombró las constantes | ya está resuelto con el puente en `totp_common.h` |
| Todos los códigos fallan | reloj desfasado | `timedatectl status` |
| Un código correcto se rechaza | anti-replay: ese paso ya se usó | esperar al siguiente |
| `permisos o propietario inseguros` | `~/.totp_auth` no es del usuario o no es 0600 | `chmod 600 ~/.totp_auth` |
| `parametros invalidos` | `/etc/totp.conf` no es de root, es escribible por otros, o tiene un valor fuera de rango | `sudo chown root:root /etc/totp.conf; sudo chmod 644 /etc/totp.conf` |
| La app muestra códigos que nunca validan | `digits` o `algorithm` distintos de 6/SHA1 | volver a los defaults y regenerar |
| `demasiados intentos` | límite de tasa activo | esperar 30 s, o `sed -i '/^" RATE/d' ~/.totp_auth` |

La herramienta de diagnóstico es `oathtool`, una implementación TOTP
independiente. Si el código que calcula coincide con el que muestra tu
teléfono, el problema no está en el seed ni en el reloj:

```bash
sudo apt install oathtool      # o dnf install / pacman -S oathtool
oathtool --totp -b "$(head -1 ~/.totp_auth)"
```

Y para ver por qué el módulo rechazó un intento, el log:

```bash
sudo journalctl -u ssh -n 20    # o -u sshd
```

---

## 10. Formato del archivo de estado

`~/.totp_auth`, modo `0600`:

```
3Y5O5OKIEZ3ILKQDXSHDAN252I4JJF7E     <- seed en Base32 (160 bits)
" TOTP_AUTH                          <- marcador
" LAST_COUNTER 59598195              <- estado anti-replay
" RATE 1788017607 2                  <- ventana e intentos contados
61204634                             <- códigos de recuperación
62735545
```

**Cambiar los parámetros:** editar `/etc/totp.conf` como root. No hace falta reiniciar nada, el módulo lo lee en cada
autenticación. Probá un login antes de cerrar la sesión de rescate.

---

## 11. Consideraciones de seguridad

### Lo que el módulo implementa

- **Seed de 160 bits** desde `getrandom()` (CSPRNG del kernel), el tamaño
  recomendado por RFC 4226 §4 R6. Se maneja `EINTR` y la lectura parcial.
- **Anti-replay**: se persiste el último paso aceptado y se rechaza
  cualquier código de un paso igual o anterior. La RFC 6238 §5.2 lo
  **exige**: el verificador no debe aceptar dos veces el mismo OTP.
- **Códigos de recuperación** de un solo uso.
- **Limitación de intentos por usuario**, persistida en disco para que
  sobreviva a reconexiones. Se chequea *después* de pedir el código:
  rechazar sin mostrar el prompt permitiría distinguir "estoy limitado" de
  "código incorrecto". Las marcas *futuras* se descartan, para que atrasar
  el reloj no bloquee a nadie para siempre.
- **Comparación en tiempo constante**: `memcmp()` corta en el primer byte
  distinto, lo que permitiría adivinar el código dígito por dígito midiendo
  latencias. Además se recorre la ventana completa aunque ya haya
  coincidencia.
- **Validación de ambos archivos en cada login**, con `fstat()` sobre el
  descriptor abierto y no `stat()` sobre la ruta, para que no haya ventana
  TOCTOU.
- **`O_NOFOLLOW`**: el estado está en el home, así que el usuario podría
  reemplazarlo por un enlace al archivo de otra persona.
- **Bajada de privilegios**: el módulo corre como root dentro de sshd, pero
  baja `euid`/`egid` al del usuario antes de tocar su archivo.
- **Escritura atómica**: temporal + `fchmod` explícito + `fsync` +
  `rename`.
- **Logs sin credenciales**: con `debug` se registra la *longitud* del
  código, nunca su valor ni el seed.
- **Fail-closed**: ante cualquier archivo inseguro o corrupto, se deniega.

### Limitaciones conocidas

- **El seed se guarda en texto plano.** Es inherente a TOTP: el verificador
  necesita el secreto para verificar. Cifrarlo solo movería el problema a
  dónde guardar la clave de cifrado.
- **El usuario puede desactivarse el 2FA** borrando `~/.totp_auth`, si
  `nullok` está activo.
- **Root puede suplantar a cualquier usuario.** Con secreto compartido no
  hay forma de evitarlo.
- **TOTP no resiste phishing en tiempo real.** Un proxy que relaya el
  código dentro de su ventana entra igual. FIDO2/WebAuthn lo resuelve
  porque ata la credencial al origen.
- **El límite de intentos reduce, no elimina, la fuerza bruta.** Con 6
  dígitos y ventana 3, la probabilidad por intento es 3/10⁶. Sin límite un
  atacante scripteado acierta casi con certeza en un día; con 3 cada 30 s
  baja a ~2,6 % por día. Convierte "minutos" en "meses", no en "nunca":
  complementa a `fail2ban` y `pam_faillock`, no los reemplaza.
- **Condición de carrera en el contador de intentos.** Dos autenticaciones
  simultáneas leen el mismo estado y ambas escriben; gana la última. Se
  resolvería con `flock()`.
- **La escritura no es atómica.** Si el sistema se corta justo mientras se
  guarda el archivo, el usuario podría quedar con un seed truncado. Se
  resolvería escribiendo a un temporal y usando `rename()`.
- **Denegación de servicio por límite de tasa.** Quien conozca un nombre de
  usuario puede mantenerlo bloqueado. Es inherente a cualquier límite por
  cuenta.
- **Sin gestión de dispositivos.** Conectar un teléfono es copiar el seed:
  no hay límite de dispositivos, ni registro, ni revocación individual.
- **El seed viaja en los backups del home.** El backup necesita al menos
  la misma protección que la máquina.

---

## 12. Desinstalación

```bash
sudo sed -i '/pam_totp.so/d' /etc/pam.d/sshd
sudo rm -f /etc/ssh/sshd_config.d/99-totp.conf
sudo systemctl restart ssh      # o sshd
sudo make uninstall
```

Ni `/etc/totp.conf` ni los `~/.totp_auth` se borran automáticamente:

```bash
sudo rm -f /etc/totp.conf
sudo find /home -maxdepth 2 -name .totp_auth -delete
```
