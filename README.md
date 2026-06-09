# WashDog Pro (Dynamic Multi-page)

Application Python WSGI autonome pour gérer des boutiques de lavage canin, leurs clients, managers, chiens, services, stocks et sauvegardes SQLite.

## Lancer
```bash
python3 server.py
```

Puis ouvrir `http://localhost:8000`.

Variables utiles :

- `PORT` : port HTTP (défaut : `8000`)
- `WASHDOG_DB` : chemin de la base SQLite (défaut : `washdog.db`)
- `WASHDOG_UPLOAD_DIR` : dossier des fichiers téléversés (défaut : `uploads`)
- `WASHDOG_IMPORT_DIR` : dossier temporaire des imports (défaut : `imports`)
- `WASHDOG_CLOUD_BACKUP_ROOT` : dossier local synchronisable contenant les backups cloud par fournisseur (`google_drive` et `proton_drive`, défaut : `cloud_backups`)
- `WASHDOG_SECRET` : secret HMAC des cookies de session. À changer en production.

## Tests
```bash
python3 -m unittest discover -s tests
```

Ou via npm :

```bash
npm test
```

## Comptes
- Admin initial : `admin@washdog.local` / `admin123`
- Les clients s'inscrivent via `/register`.

Après la première connexion, changez le mot de passe admin dans `/admin/security` et définissez `WASHDOG_SECRET` avec une valeur forte.

## Sécurité / accès
- `/shops` : public (vitrines boutiques)
- `/admin` redirige vers `/admin/dashboard` : privé (admin et managers référents)
- `/admin/dashboard` : tableau de bord par boutique avec accès complet admin et vue filtrée manager, statistiques dynamiques en diagrammes à barres ou graphiques camembert
- `/admin/templates` : gestion des templates (liste, création, édition/modification, suppression)
- `/admin/shops` : gestion des boutiques (liste, création, édition/modification, suppression, photos, mode Libre service/Réservation) et onglet `Stock` pour la gestion du stock par boutique avec ajout/retrait par scan code-barres
- `/admin/services` : gestion des services des boutiques par l'admin et les managers référents (prestations de base, spécialisées et bien-être)
- `/admin/clients` : gestion des clients (liste, création, édition/modification, suppression, affichage tableau/vignettes, recherche, tri, exports CSV/Markdown/PDF, import vCard 3.0 dans le formulaire de création)
- `/admin/managers` : gestion des managers (liste, création, édition/modification, suppression, boutiques de référence)
- `/admin/dogs` : gestion des chiens par l'admin et les managers référents de boutique (liste, création, édition/modification, suppression)
- `/admin/database` : gestion de la base de données (sauvegarde locale, backups cloud complets/incrémentiels vers Google Drive ou Proton Drive via dossier synchronisable, restauration cloud, import validé par `PRAGMA quick_check`, export)
- `/admin/security` : gestion de la sécurité (mot de passe admin, logo d'accueil, nom/taille de base, sauvegarde/import/export et backups/restaurations cloud)
- `/client` et `/dogs` : privés (client connecté)

## Base de données
- SQLite locale : `washdog.db` par défaut, configurable par `WASHDOG_DB`
- Backups cloud : l'application écrit les fichiers dans `WASHDOG_CLOUD_BACKUP_ROOT/google_drive` ou `WASHDOG_CLOUD_BACKUP_ROOT/proton_drive`; pointez ce dossier vers un client de synchronisation Google Drive ou Proton Drive côté serveur.
- Tables : `users`, `templates`, `shops`, `dogs`, `sessions`, `settings`, `manager_shops`, `stock_items`, `shop_services`
- Le logo de la page d'accueil est conservé dans `settings.home_logo_path` et les fichiers importés sont stockés dans `uploads/`.
