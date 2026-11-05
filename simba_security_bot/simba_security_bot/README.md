# SIMBA SECURITY BOT

Bot Discord de protection pour un serveur de 100 à 1 000 membres. Python + discord.py + SQLite + Docker.

## Fonctions incluses

- Anti-Raid : détecte les arrivées rapides, applique une quarantaine temporaire et signale les comptes récents.
- Anti-Nuke : surveille certaines actions d'audit (suppression de salons/rôles, création de webhooks, ajout de bots, bans/kicks répétés) et retire les rôles modifiables de l'auteur non whitelisté.
- Anti-Spam : détecte le flood et les mentions excessives, supprime le message si possible et applique un timeout progressif.
- Whitelist : seul le propriétaire du serveur peut modifier la liste.
- Logs : alertes dans un salon configuré.
- Lockdown : sauvegarde les overwrites @everyone des salons texte, bloque l'envoi de messages et permet de restaurer les permissions enregistrées.

> Aucun bot ne peut garantir une sécurité à 100 %. Les protections natives Discord, une bonne configuration des rôles et la sécurité des comptes administrateurs restent indispensables.

## 1. Créer l'application Discord

1. Ouvre https://discord.com/developers/applications
2. New Application → donne-lui le nom `SIMBA SECURITY`.
3. Dans l'onglet Bot, crée/réinitialise le token. Garde-le secret.
4. Dans Privileged Gateway Intents, active **Server Members Intent** et **Message Content Intent**.
5. Ajoute le bot au serveur avec les permissions minimales nécessaires :
   - View Channels
   - Send Messages
   - Embed Links
   - Read Message History
   - View Audit Log
   - Manage Roles
   - Moderate Members
   - Manage Channels (uniquement si tu souhaites utiliser le lockdown)
6. Place le rôle du bot au-dessus du rôle de quarantaine et des rôles qu'il doit pouvoir retirer. Ne lui donne pas Administrator.

## 2. Préparer le serveur

1. Crée un salon privé, par exemple `#security-logs`, visible uniquement par toi et les modérateurs de confiance.
2. Copie son ID (active le mode développeur Discord, clic droit sur le salon → Copier l'identifiant).
3. Crée un rôle `Quarantaine` sans permissions dangereuses. Dans ses permissions de salon, refuse l'accès aux salons communautaires et autorise uniquement un salon d'appel/assistance si nécessaire.
4. Place le rôle `Quarantaine` sous le rôle du bot.
5. Copie les ID du salon et du rôle.

## 3. Configurer

Copie `.env.example` vers `.env`, puis renseigne :
- `DISCORD_TOKEN`
- `LOG_CHANNEL_ID`
- `QUARANTINE_ROLE_ID`

Ne publie jamais `.env`, le token ou une capture d'écran contenant le token.

## 4. Déployer sur un hébergement cloud Docker

Sur un VPS ou un service cloud compatible Docker :

```bash
docker compose up -d --build
docker compose logs -f
```

Active le stockage persistant pour `/app/data` afin de conserver la whitelist et l'état du lockdown entre redémarrages. Le bot redémarre automatiquement si le processus s'arrête.

## 5. Commandes slash

- `/security status` : état des protections.
- `/security allow-add @membre` : ajouter à la whitelist (propriétaire uniquement).
- `/security allow-remove @membre` : retirer de la whitelist (propriétaire uniquement).
- `/security lockdown` : bloquer temporairement l'envoi de messages pour @everyone dans les salons texte (propriétaire uniquement).
- `/security unlock` : restaurer les permissions enregistrées (propriétaire uniquement).

## 6. Réglages et limites importantes

- Les seuils Anti-Raid et Anti-Nuke sont configurables dans `.env`.
- La quarantaine des comptes récents est désactivée si `QUARANTINE_ROLE_ID=0`.
- Le bot ne peut pas retirer les rôles au-dessus de son propre rôle, les rôles gérés par des intégrations, ni agir sur le propriétaire.
- L'Anti-Nuke intervient après détection : il ne peut pas annuler une suppression déjà effectuée.
- Les logs d'audit Discord peuvent arriver avec un délai ou des informations incomplètes. Teste les seuils avec un compte de test.
- Le filtre Anti-Spam repose sur Message Content Intent. Les liens ne sont pas automatiquement considérés comme malveillants : ajoute AutoMod et une liste de domaines interdits adaptée à ta communauté.
- La restauration du lockdown remet les permissions @everyone sauvegardées au moment du verrouillage. Évite de modifier ces permissions manuellement pendant le lockdown.

## 7. Vérifications avant mise en production

- Teste le bot sur un serveur privé de test.
- Vérifie que `#security-logs` est invisible aux membres ordinaires.
- Vérifie la hiérarchie des rôles.
- Vérifie les intents dans le Developer Portal.
- Teste `/security lockdown`, puis `/security unlock`.
- Active Discord AutoMod et les protections anti-raid natives disponibles dans les paramètres du serveur.
- Active l'authentification à deux facteurs sur les comptes propriétaires et modérateurs.
- N'accorde jamais Administrator à un bot ou à un modérateur sans nécessité absolue.

## Dépendances

- Python 3.12
- discord.py 2.x
- python-dotenv
- SQLite (inclus avec Python)
