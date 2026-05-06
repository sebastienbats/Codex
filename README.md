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
- `/admin` : privé (admin uniquement)
- `/client` et `/dogs` : privés (client connecté)

## Base de données
- SQLite locale : `washdog.db`
- Tables : `users`, `templates`, `shops`, `dogs`, `sessions`
