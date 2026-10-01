PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

.PHONY: install uninstall run deps

# Install OS packages used by NETUI. Package installation may ask for sudo.
deps:
	@set -eu; \
	if command -v pacman >/dev/null 2>&1; then \
		missing=""; \
		for cmd_pkg in "python:python" "ping:iputils" "ip:iproute2" "smbclient:smbclient"; do \
			cmd=$${cmd_pkg%%:*}; pkg=$${cmd_pkg#*:}; \
			command -v "$$cmd" >/dev/null 2>&1 || missing="$$missing $$pkg"; \
		done; \
		if [ -n "$$missing" ]; then echo "Installing required packages:$$missing"; sudo pacman -S --needed --noconfirm $$missing; fi; \
	elif command -v apt-get >/dev/null 2>&1; then \
		missing=""; \
		command -v python3 >/dev/null 2>&1 || missing="$$missing python3"; \
		command -v ping >/dev/null 2>&1 || missing="$$missing iputils-ping"; \
		command -v ip >/dev/null 2>&1 || missing="$$missing iproute2"; \
		command -v smbclient >/dev/null 2>&1 || missing="$$missing smbclient"; \
		if [ -n "$$missing" ]; then echo "Installing required packages:$$missing"; sudo apt-get update; sudo apt-get install -y $$missing; fi; \
	elif command -v dnf >/dev/null 2>&1; then \
		missing=""; \
		command -v python3 >/dev/null 2>&1 || missing="$$missing python3"; \
		command -v ping >/dev/null 2>&1 || missing="$$missing iputils"; \
		command -v ip >/dev/null 2>&1 || missing="$$missing iproute"; \
		command -v smbclient >/dev/null 2>&1 || missing="$$missing samba-client"; \
		if [ -n "$$missing" ]; then echo "Installing required packages:$$missing"; sudo dnf install -y $$missing; fi; \
	else \
		echo "Unsupported package manager. Install Python 3, iputils, iproute2 and smbclient manually."; exit 1; \
	fi

install: deps
	@command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
	@mkdir -p "$(BINDIR)"
	@install -m 755 netui.py "$(BINDIR)/netui"
	@echo "Installed: $(BINDIR)/netui"
	@case ":$$PATH:" in *":$(BINDIR):"*) ;; *) echo "Note: add $(BINDIR) to your PATH to run 'netui'." ;; esac

uninstall:
	@rm -f "$(BINDIR)/netui"
	@echo "Removed $(BINDIR)/netui"

run:
	@python3 netui.py
