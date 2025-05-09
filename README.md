
# 🍸 AuthService – Cocktail Débâcle

Microservizio responsabile della **gestione dell'autenticazione**, della generazione di **token JWT**, e della gestione dei **refresh token** per la webapp *Cocktail Débâcle*.

---

## 🔧 Funzionalità principali

- ✅ Registrazione utenti
- 🔐 Login con hash SHA-256
- 🔁 Refresh dei token JWT
- 🚪 Logout (revoca refresh token)
- 🧑‍💻 Creazione automatica utente admin al primo avvio
- 🌍 Comunicazione con `user-profile-service`
- ⚙️ Migrazione automatica del DB PostgreSQL all'avvio

---

## 📁 Struttura del progetto

```
AuthService/
├── Controllers/        # API endpoints (AuthController)
├── Data/               # DbContext per Entity Framework Core
├── Models/             # Modelli dati: User, RefreshToken, Request DTOs
├── Services/           # Client HTTP per il profilo utente
├── Program.cs          # Configurazione app, auth, db, migrazione, seed admin
├── appsettings.json    # Configurazione default
├── Dockerfile          # Build e run container .NET 8
```

---

## 🚀 Avvio rapido

### Prerequisiti

- Docker + Docker Compose
- Git

### 🧪 Avvio con Docker Compose

Clona il progetto e avvia:

```bash
git clone <url-del-repo>
cd <repo>/AuthService
docker compose up --build
```

---

## ⚙️ Configurazione (tutto già pronto)

Tutte le configurazioni sono **versionate** nei file:

- `appsettings.json`: valori di default (incluso JWT e AdminUser vuoto)
- `docker-compose.yml`: override tramite variabili d'ambiente

### 🔑 Variabili JWT

```yaml
- JWT__Key=questa-e-una-chiave-super-segreta-lunga
- JWT__Issuer=CocktailDebacle
- JWT__Audience=CocktailDebacleUsers
```

### 👑 Creazione utente admin

All’avvio, se **non esiste un utente con l’email indicata**, viene creato un utente admin con i seguenti parametri (da `docker-compose.yml`):

```yaml
- AdminUser__Email=admin@cocktail.local
- AdminUser__Username=admin
- AdminUser__Password=SuperSegreta123!
```

---

## 🧪 API disponibili (via Swagger)

Quando il container è avviato, puoi esplorare le API su:

```
http://localhost:<porta>/swagger
```

### 🔹 POST /api/auth/register

Registra un nuovo utente e crea anche il profilo utente.

### 🔹 POST /api/auth/login

Autentica l’utente e restituisce JWT + refresh token.

### 🔹 POST /api/auth/refresh

Restituisce un nuovo token usando un refresh token valido.

### 🔹 POST /api/auth/logout

Revoca il refresh token.

### 🔹 GET /api/auth/exists/{id}

Verifica se un utente esiste per ID.

### 🔹 GET /api/auth/me (protetto)

Restituisce i dati dell’utente loggato (dal token JWT).

---

## 🛠 Database

Usa PostgreSQL con Entity Framework Core:

- Tabella `Users`
- Tabella `RefreshTokens`

Il container `postgres` è già incluso in `docker-compose.yml`:
```yaml
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: authdb
```

---

## 🔄 Migrazione automatica

All'avvio il microservizio:
1. attende il DB PostgreSQL (con retry)
2. applica eventuali migrazioni EF
3. crea l'utente admin se non presente

---

## 📦 Costruzione manuale (opzionale)

Per testare fuori da Docker:

```bash
dotnet restore
dotnet build
dotnet ef database update
dotnet run
```

---

## 📣 Note finali

- Questo microservizio fa parte di un ecosistema più ampio.
- Comunica con `user-profile-service` per la creazione e lettura del profilo utente.
- JWT include i claims `alcoholAllowed`, `profilingAllowed` e `isAdmin` per filtrare il comportamento lato client.
