# Backend Apps Script: deploy automatico

Ogni modifica a `apps-script/*.gs`, `apps-script/*.html` o `apps-script/appsscript.json` che arriva su `main` viene pubblicata da sola sulla web app esistente. L'URL `/exec` non cambia.

Flusso di una modifica: branch → pull request → merge su `main` → controllo di sintassi → `clasp push` → nuova versione sulla distribuzione esistente → verifica che la web app risponda.

## Configurazione (una sola volta, circa 15 minuti)

**1. Abilita l'API di Apps Script**
Apri https://script.google.com/home/usersettings e attiva "Google Apps Script API".

**2. Installa gli strumenti sul PC**
Installa Node.js (versione LTS), poi da un terminale:

```
npm install -g @google/clasp@2.4.2
clasp login
```

Accedi con l'account Google proprietario del progetto Apps Script. Il comando crea il file `.clasprc.json` nella cartella personale (Windows: `C:\Users\<nome>\.clasprc.json`).

**3. Scarica lo stato attuale del backend**
Il progetto in produzione è la fonte di verità: parti da lì, non da vecchie copie.

```
mkdir backend && cd backend
clasp clone <SCRIPT_ID>
```

`SCRIPT_ID` si trova in Apps Script → Impostazioni progetto → ID script. Otterrai `Code.gs`, `print_template.html` e `appsscript.json`.

**4. Controlla i file prima di caricarli (importante)**
Il repository è PUBBLICO. Apri `Code.gs` e verifica che non contenga nessuna chiave, password o segreto scritto nel codice (per esempio una vecchia funzione `setupSecrets` con i valori). I segreti devono stare solo nelle Proprietà script di Apps Script. Il workflow si rifiuta comunque di pubblicare se trova `setProperty('...')` con i nomi dei segreti noti.

**5. Carica i file nel repository**
Su GitHub: cartella `apps-script` → Add file → Upload files → carica `Code.gs`, `print_template.html` e `appsscript.json` (non `.clasp.json`) → Commit su un nuovo branch e apri la pull request.
Non fare il merge finché il punto 6 non è completo.

**6. Aggiungi i segreti su GitHub**
Settings → Secrets and variables → Actions:

| Tipo | Nome | Valore |
|---|---|---|
| Secret | `CLASPRC_JSON` | contenuto completo del file `.clasprc.json` |
| Secret | `SCRIPT_ID` | ID script (punto 3) |
| Secret | `DEPLOYMENT_ID` | ID della distribuzione web app: è la parte tra `/s/` e `/exec` nell'URL della web app |
| Variable | `WEBAPP_URL` | URL completo della web app, che termina con `/exec` |

Non incollare mai questi valori in chat.

**7. Primo deploy**
Fai il merge della pull request del punto 5. In Actions vedrai "Deploy Apps Script": se tutti i passaggi hanno la spunta verde, il backend è stato aggiornato.

## Sicurezza

- `CLASPRC_JSON` dà accesso al tuo account Google per Apps Script e Drive: trattalo come una password. Se pensi che sia trapelato, revoca l'accesso da https://myaccount.google.com/permissions e rifai `clasp login`.
- I segreti di GitHub non sono disponibili nelle pull request da fork. Resta comunque vero che chi ha accesso in scrittura al repository può modificare il workflow: dai accesso solo a persone fidate.
- Facoltativo: in Settings → Environments → `production` aggiungi te stesso come "Required reviewer". Ogni deploy aspetterà un tuo clic di approvazione.

## Annullare un aggiornamento

Su GitHub apri la pull request che ha causato il problema e usa **Revert**: crea una nuova pull request con la modifica opposta. Facendone il merge, il backend torna alla versione precedente.

## Cose da sapere

- `clasp push` sostituisce tutto il contenuto del progetto con i file della cartella: se un file esiste solo su Apps Script (per esempio `print_template.html`) e non nel repository, viene eliminato. Per questo il workflow si ferma se mancano `Code.gs`, `appsscript.json` o `print_template.html`.
- Le Proprietà script (chiavi, segreti) non vengono toccate dal deploy.
- Le impostazioni della web app ("Esegui come", "Chi ha accesso") stanno in `appsscript.json`: tienilo nel repository.
- Se aggiungi un nuovo file `.gs` o `.html`, mettilo in `apps-script/`.
