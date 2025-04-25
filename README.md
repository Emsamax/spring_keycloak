REFAIRE LE PROJECT, 
REFAIRE LA SECURITY CONFIG SELON LES COMMENTAIRES 
REMETTRE LES BONS URI DANS PROPERTIES 

@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		//oauthserver
		//reqquestmatchers
		//logouthandler
		//authoriser les ressources internes pr leaflet + rajouter le path /templates/**
		//bean pour decoder jwt dans oidc user
		return http.build();
	}
 spring.security.oauth2.client.registration.keycloak.provider=
spring.security.oauth2.client.registration.keycloak.authorization-grant-type=
spring.security.oauth2.client.registration.keycloak.client-id=
spring.security.oauth2.client.registration.keycloak.client-secret=
spring.security.oauth2.client.registration.keycloak.scope=openid, profile, email


A FAIRE EN PLUS POUR TERMINER
-> PAS DE CONSTANTES POUR LES ROLES JUSTE METTRE hasrole('adm')
-> PAS D'END POINT PUBLIQUE CONNEXION OBLIGATOIRE  
-> CODE PLUS PROPRE -> UTILISER VAR LAMBDAS ET :: SI POSSIBLE ET API STREAM 
-> LIMITER LA VISIBILITE DES ELEMENTS EN FONCTION DES ROLES ET/OU DES PERMISSIONS -> EX ADMIN AVEC PERMISSION WRITE
-> /!\ NE RIEN ECRIRE EN DUR DANS LE CODE? SOIT CONSTANTE OU VARIABLES DANS FICIERS DE CONFIGURATION

NOTES -> COMMENTAIRES EN ANGLAIS ET NOM DE VARIABLES PLUS PROPRES 
