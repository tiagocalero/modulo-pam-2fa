# Makefile — pam_totp
#
# make
# sudo make install
# sudo make uninstall
# make clean

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wno-unused-parameter
SRC = src

MODULE = pam_totp.so
TOOL = totp-admin

# buscamos en que directorio se guardan los modulos PAM, varian entre distribuciones de Linux */
SECURITYDIR ?= $(shell \
    for d in /usr/lib/$$(uname -m)-linux-gnu/security /usr/lib64/security \
             /usr/lib/security /lib64/security /lib/security; do \
        [ -f "$$d/pam_permit.so" ] && echo "$$d" && exit 0; \
    done; echo /usr/lib/security)

BINDIR ?= /usr/local/bin
CONFFILE ?= /etc/totp.conf

.PHONY: all install uninstall clean

all: $(MODULE) $(TOOL)

$(MODULE): $(SRC)/pam_totp.c $(SRC)/totp_common.c $(SRC)/totp_crypto.c $(SRC)/totp_common.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $(SRC)/pam_totp.c $(SRC)/totp_common.c $(SRC)/totp_crypto.c -lpam -lcotp -lgcrypt

$(TOOL): $(SRC)/totp-admin.c $(SRC)/totp_common.c $(SRC)/totp_crypto.c $(SRC)/totp_common.h
	$(CC) $(CFLAGS) -o $@ $(SRC)/totp-admin.c $(SRC)/totp_common.c $(SRC)/totp_crypto.c -lpam -lcotp -lgcrypt

install: all
	@if [ "$$(id -u)" != "0" ]; then echo "ERROR: usa sudo"; exit 1; fi
	install -m 0644 $(MODULE) $(SECURITYDIR)/
	install -m 0755 $(TOOL) $(BINDIR)/
	install -m 0644 totp-admin.pam /etc/pam.d/totp-admin
	@if [ -f $(CONFFILE) ]; then \
	    echo "  ($(CONFFILE) ya existe)"; \
	else \
	    install -m 0644 totp.conf $(CONFFILE); \
	fi
	@command -v restorecon >/dev/null 2>&1 && restorecon -F $(SECURITYDIR)/$(MODULE) 2>/dev/null || true
	@echo "Instalado:"
	@echo "$(SECURITYDIR)/$(MODULE)"
	@echo "$(BINDIR)/$(TOOL)"
	@echo "$(CONFFILE)"

uninstall:
	rm -f $(SECURITYDIR)/$(MODULE) $(BINDIR)/$(TOOL)
	@echo "Recorda borrar la linea de /etc/pam.d/sshd."
	@echo "$(CONFFILE) y los ~/.totp_auth NO se borraron."

clean:
	rm -f $(MODULE) $(TOOL)
