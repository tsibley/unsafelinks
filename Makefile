# 127.0.0.13 in /etc/hosts
HOST ?= nam02.safelinks.protection.outlook.com
USER ?= $(shell id -u)
GROUP ?= $(shell id -g)

server: key.pem cert.pem
	sudo starman --listen "$(HOST):443" --enable-ssl --ssl-key key.pem --ssl-cert cert.pem --user "$(USER)" --group "$(GROUP)"

key.pem req.pem:
	openssl req -newkey rsa:4096 -keyout key.pem -nodes -out req.pem -sha256 -subj "/CN=$(HOST)"

cert.ext:
	echo "subjectAltName = DNS:$(HOST)" > cert.ext

cert.pem: ~/.mitmproxy/mitmproxy-ca.pem key.pem req.pem cert.ext
	openssl x509 -req -CA ~/.mitmproxy/mitmproxy-ca.pem -CAcreateserial -in req.pem -out cert.pem -extfile cert.ext
