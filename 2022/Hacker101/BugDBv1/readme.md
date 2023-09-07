## BugDB v1 

Ce challenge est basé sur GraphQL (https://graphql.org/). <br><br>
La première chose que j'ai essayé de faire, est une introspection pour pouvoir déduire le schéma et comprendre quelles types de requêtes sont possibles de faire sur GraphQL.
<br><br>

```
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```
<br>
Voici le résultat obtenu : 
<img src="https://image.noelshack.com/fichiers/2021/42/5/1634916313-introspection.png">
Par la suite, j'ai utilisé GraphQL Voyager pour comprendre un peu mieux le résultat obtenu. 
<br>
<img src="https://image.noelshack.com/fichiers/2021/42/5/1634916294-graphql-voyager.png">
En interrogeant les différents endpoints, j'obtiens ce résultat là: 

<img src="https://image.noelshack.com/fichiers/2021/42/5/1634916810-result.png">

<br><br><br>
Quelques ressources qui m'ont aidé pour ce challenge: <br>
https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-endpoint-bug-bounty/ <br>
https://graphql.org/learn/introspection/ <br>
https://book.hacktricks.xyz/pentesting/pentesting-web/graphql

