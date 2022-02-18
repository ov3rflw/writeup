# Writeup Vulnnet-Internal

<ins>Plateforme</ins>: **TryHackMe**\
<ins>Nom</ins>: **VulnNet-Internal**\
<ins>Difficulté</ins>: **Easy**\
<ins>Infos</ins>: **Linux, Énumération, Pivoting, Escalade de privilèges**

## Recon | NMAP

![image](https://user-images.githubusercontent.com/68467919/154627971-38eec5bd-2c4b-4bf2-941d-a6aea3e07968.png)

Premièrement, notre scan NMAP nous indique plusieurs choses intéressantes. La première est la découverte d'un serveur **SMB** (samba). Nous remarquons également que notre machine cible fait tourner **Redis**. Un serveur **NFS** est également présent !  

## Port 139, 445 | SMB 

```bash
enum4linux -A internal.thm
```
![image](https://user-images.githubusercontent.com/68467919/154628810-c19e634f-444d-4c63-bbf8-c02d886098f6.png)

Nous pouvons essayer d'accéder au dossier __shares__

![image](https://user-images.githubusercontent.com/68467919/154628849-e2c58761-52a9-48c1-a7a5-89ecee179b49.png)

Téléchargeons les fichiers présents dans le dossier grâce à la commande : 
```bash
get foo.txt
```

## Flag 1 
<ins>Hint</ins>: It's stored inside one of the available services.

![image](https://user-images.githubusercontent.com/68467919/154629136-f9095e72-bbf2-430b-98d3-4d4476625f50.png)

## Mount | NFS

```bash
mkdir nfs
sudo mount -t nfs 10.10.155.81:/ nfs
```
![image](https://user-images.githubusercontent.com/68467919/154630022-8d363157-4036-465b-9d81-19e06955b94e.png)

Jettons un oeil au fichier **redis.conf**

![image](https://user-images.githubusercontent.com/68467919/154630074-f61b4f02-eec7-4ee0-9133-e24600199251.png)

Super, nous avons trouvé le requirepass qui pourrait nous permettre de nous connecter à Redis ! 

## redis-dump | Redis

![image](https://user-images.githubusercontent.com/68467919/154630495-9739bce7-2fa8-44df-8f38-76f016d9e517.png)

Donc nous pouvons nous connecter à Redis avec ce mot de passe. Après quelques recherches intéressantes pour essayer de trouver une vulnérabilité sur Redis, il est possible de DUMP la base de donnée avec le tools **redis-dump** si nous possédons un mot de passe.

## Flag 2
<ins>Hint</ins>: It's stored inside a database of one of the services.

![image](https://user-images.githubusercontent.com/68467919/154630600-9e78a753-87fe-4072-95d6-b4640d9c04be.png)
  
Après avoir dump la base de donnée, nous pouvons remarquer que des strings en base64 peuvent être décodées. Essayons ça.

![image](https://user-images.githubusercontent.com/68467919/154630850-84ae84f9-69df-4391-83ac-7765a82f191d.png)

Nous obtenons un mot de passe qui a été utilisé avec RSYNC. Après quelques recherches sur quoi faire avec RSYNC, je vois qu'il est possible de télécharger, modifier, ajouter des fichiers distants depuis notre machine.

## Download & Upload | RSYNC

![image](https://user-images.githubusercontent.com/68467919/154631197-4b196780-30b4-4b47-91ba-2d1eea60d0af.png)

![image](https://user-images.githubusercontent.com/68467919/154631308-14f76fdb-d4c7-43e8-af2f-5f8dafd2a069.png)

Pour récapituler un peu, nous avons télécharger les répertoires de l'utilisateur **sys-internal**. Nous pourrions par exemple upload un "authorization_keys" dans son .ssh pour essayer de se connecter à sa session via SSH.

![image](https://user-images.githubusercontent.com/68467919/154631873-b4182fe2-4b3f-47d4-932f-1a21155529a0.png)

![image](https://user-images.githubusercontent.com/68467919/154631906-75172828-6d51-432a-b230-2184bcd2e366.png)

Après avoir un peu énuméré ma session, voir ce que je pouvais faire, je me suis rappelé que nous devions faire du pivoting pendant cette room. En regardant quels ports est actuellement sur écoute, je remarque un port **8111**. Essayons de bind un de nos ports pour pouvoir accéder à ce service.

## Pivoting & Reverse-Shell | Port 8111 | TeamCity

```bash
ssh -i id_rsa -L 8111:localhost:8111 sys-internal@10.10.155.81
```

![image](https://user-images.githubusercontent.com/68467919/154632635-c6ab18fc-300e-4b1b-b177-d429792facb6.png)

Bon, nous n'avons pas d'username ni de mot de passe pour se connecter à TeamCity. Je vois qu'il est possible de se connecter en "Super user", mais malheureusement, la page nous demande un token. En énumérant les fichiers de configurations présents dans le dossier TeamCity sur notre session SSH.

```bash
grep -rnw '/TeamCity' -e 'token'
```

![image](https://user-images.githubusercontent.com/68467919/154632959-cc1860f5-116f-402d-ad10-d20461916b33.png)

**TOKEN TROUVÉ !** Connectons nous maintenant sur TeamCity.

Suite à de longues recherches sur TeamCity, je tombe sur une vidéo qui me montre clairement comment exécuter des commandes en "buildant" un projet. Et si nous tentions un reverse-shell? 

Tout d'abord, nous devrions créer un projet comme ceci : 
![image](https://user-images.githubusercontent.com/68467919/154633456-08e829e4-147a-40c1-8e70-df256a51e3a8.png)
Ensuite, créer une configuration pour build notre projet : 
![image](https://user-images.githubusercontent.com/68467919/154633563-77e28023-db11-4a92-8a2c-edc4ebfd243b.png)
![image](https://user-images.githubusercontent.com/68467919/154633581-828c1cb7-2a8c-4365-9316-371e86ca405e.png)
Dans "**Runner type**", choisir "**Command Line**" puis rentrer votre reverse-shell. (j'ai essayé un reverse-shell en bash, et avec netcat mais ça n'a pas fonctionné)
![image](https://user-images.githubusercontent.com/68467919/154633634-e042d9c8-f347-47f9-ac17-bdbda890691c.png)
![image](https://user-images.githubusercontent.com/68467919/154633867-abc3b650-7372-4dd7-8c17-06f26d7fe19a.png)

**BINGO!!!**

### Notes personnelles

CTF très sympa qui nous impose de switch sur plusieurs services pour accéder au root. Cette room m'a permis de découvrir comment fonctionne certains services et quel type de vulnérabilité pouvait être utilisé.

## Ressources

https://youtu.be/XvVymXvEgno \
https://book.hacktricks.xyz/pentesting/6379-pentesting-redis \
https://github.com/delano/redis-dump \
https://linuxize.com/post/how-to-mount-an-nfs-share-in-linux/ \
https://book.hacktricks.xyz/pentesting/873-pentesting-rsync \
https://www.ssh.com/academy/ssh/tunneling/example
