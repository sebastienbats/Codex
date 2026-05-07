# WashDog Pro (Dynamic Multi-page)

## Lancer
```bash
python3 server.py
```

Puis ouvrir `http://localhost:8000`.

## Comptes
- Admin initial : `admin@washdog.local` / `admin123`
- Les clients s'inscrivent via `/register`.

## Sécurité / accès
- `/shops` : public (vitrines boutiques)
- `/admin` redirige vers `/admin/templates` : privé (admin uniquement)
- `/admin/templates` : gestion des templates (liste, création, édition/modification, suppression)
- `/admin/shops` : gestion des boutiques (liste, création, édition/modification, suppression, photos) et onglet `Stock` pour la gestion du stock par boutique
- `/admin/clients` : gestion des clients (liste, création, édition/modification, suppression, affichage tableau/vignettes, recherche, tri, exports CSV/Markdown/PDF)
- `/admin/managers` : gestion des managers (liste, création, édition/modification, suppression, boutiques de référence)
- `/admin/dogs` : gestion des chiens par l'admin et les managers référents de boutique (liste, création, édition/modification, suppression)
- `/admin/database` : gestion de la base de données (sauvegarde, import, export)
- `/admin/security` : gestion de la sécurité (mot de passe admin, logo d'accueil, nom/taille de base, sauvegarde/import/export)
- `/client` et `/dogs` : privés (client connecté)

## Base de données
- SQLite locale : `washdog.db`
- Tables : `users`, `templates`, `shops`, `dogs`, `sessions`, `settings`, `manager_shops`, `stock_items`
- Le logo de la page d'accueil est conservé dans `settings.home_logo_path` et les fichiers importés sont stockés dans `uploads/`.
