# Modern .ssh/config by @benmontour

## Defaults

Host *

### Ignore Unknown Config Options. This suppresses an error on non-macOS systems

IgnoreUnknown UseKeychain

### Specify default IdentityFile. This will be used for any host where we don't specify a specific IdentityFile

 IdentityFile ~/.ssh/id_ed25519_sk

### Force use of IdentityFiles defined within this config only

 IdentitiesOnly yes

### OpenSSH should be configured to the network family. Set it to inet if you use IPv4 only. For IPv6 only set it to inet6. For both set it to any

 AddressFamily inet

### Specify default port the SSH client should connect to. This will be used unless a specific port is called out for a host within this file

 Port 22

### Only SSH protocol version 2 connections should be allowed. Version 1 of the SSH protocol contains security vulnerabilities

 Protocol 2

### Prevents batch ssh jobs where no user is present to supply a passphrase. Setting to no makes sure passphrase querying is enabled

 BatchMode no

### Don't automatically add new hosts keys to the list of known hosts. Setting to ask to require user verification to add a host to the known_hosts file

 StrictHostKeyChecking ask

### Make sure that SSH checks the host IP address in the known_hosts file, this avoids potential DNS spoofing

 CheckHostIP yes

### Show ASCII art representation of remote host fingerprint

 VisualHostKey yes

### Ask to import other HostKeys that the host supports. May help move to a more secure key exchange if the host supports it but you didn't have the key imported

UpdateHostKeys ask

### Force use of public key authentication by default

 PubkeyAuthentication yes

### Avoid password-based authentication whenever possible. Use ssh keys or certificates only

 PasswordAuthentication no

### Disable Challenge/Response Authentication

 ChallengeResponseAuthentication no

### Disable GSSAPI authentication when unused

 GSSAPIAuthentication no
 GSSAPIDelegateCredentials no

### Disable Host based authentication. This limits potential lateral movement if your host is compromised. There are better solutions out there with modern tools

 HostbasedAuthentication no

### Avoid using SSH tunnels by default

 Tunnel no

### Do not permit any local command execution

 PermitLocalCommand no

### Hash the known_hosts file to prevent potential information exposure in case of your system being compromised

 HashKnownHosts yes

### Disable agent forwarding by default, since local agent could be accessed through forwarded connection

 ForwardAgent no

### Disable X11 forwarding, since local X11 display could be accessed through forwarded connection

 ForwardX11 no
 ForwardX11Trusted no

### Server Keep Alive for 15min (60 sec x 15 counts)

 ServerAliveInterval 60
 ServerAliveCountMax 15

### This shouldn't be needed anymore in modern OpenSSH versions. I leave it here because it also doesn't hurt anything and just makes me feel better. It is a workaround for SSH Client bugs CVE-2016-0777 and CVE-2016-0778

 UseRoaming no

### Add keys to SSH agent

 AddKeysToAgent yes

### If on macOS, and using the built in OpenSSH client, then use Apple Keychain to store SSH key passwords. This doesn't work with our upgraded OpenSSH client that allows us to use hardware backed SSH keys though. Left here as it doesn't hurt anything

 Match exec "uname -s | grep Darwin"
 UseKeychain yes

### Only use strong ciphers like chacha20 & aes256-gcm

 Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com

### Only use HMAC SHA2 Encrypt-then-MAC (EtM)

 MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

### Only use DH over curve25519

 KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org

### Only use ed25519 or RSA SHA2

 HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

### Only use hardware key backed ed25519 or normal ed25519

 PubkeyAcceptedKeyTypes sk-ssh-ed25519@openssh.com,ssh-ed25519

## Host specific configs

Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_github_ed25519_sk
