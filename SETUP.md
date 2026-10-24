# Setting up DocuTrust on a new Windows PC

A step-by-step guide for running this project from a fresh machine. Allow about
20 minutes, most of which is downloads.

If anything goes wrong, jump to [Troubleshooting](#troubleshooting) — the
problems listed there are ones that actually occurred during development, not
hypotheticals.

---

## What you need to install

Four tools. Three come from `winget`, which is built into Windows 11.

Open **PowerShell** and run these one at a time. Each will ask for administrator
permission — that is expected.

### 1. Java 21

```powershell
winget install --id Microsoft.OpenJDK.21 --exact
```

### 2. Node.js

```powershell
winget install --id OpenJS.NodeJS.LTS --exact
```

### 3. Git

```powershell
winget install --id Git.Git --exact
```

### 4. Maven — this one is NOT in winget

`winget install Apache.Maven` does **not** work; the package does not exist.
Download and extract it manually instead:

```powershell
New-Item -ItemType Directory -Path C:\tools -Force
Invoke-WebRequest -Uri "https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.zip" -OutFile "$env:TEMP\maven.zip"
Expand-Archive -Path "$env:TEMP\maven.zip" -DestinationPath C:\tools -Force
```

Then add it to your PATH permanently:

```powershell
[Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';C:\tools\apache-maven-3.9.9\bin', 'User')
```

---

## Close PowerShell and open a new one

**This step matters.** Windows installers update the PATH, but windows that are
already open keep the old copy. Nothing you just installed will be found until
you open a fresh window.

Then check all four tools are visible:

```powershell
java -version; mvn -v; node -v; git --version
```

You should see version numbers for all four. If any says "not recognized", see
[Troubleshooting](#troubleshooting).

---

## Get the project

```powershell
cd $HOME\Desktop
git clone https://github.com/aanyaarney/docutrust.git
cd docutrust
```

---

## Run it

Double-click **`start-docutrust.bat`** in the project folder.

Or from a terminal:

```powershell
.\start-docutrust.bat
```

It opens two windows (backend and frontend), waits until the backend is actually
answering, then opens your browser automatically.

**The first run takes several minutes** — Maven downloads around 200 MB of
dependencies and npm installs the frontend packages. Later runs take about 30
seconds. You will see `... still starting [1]`, `[2]`, `[3]` while it waits;
that is normal.

If npm has never run in this copy, install the frontend packages first:

```powershell
cd frontend
npm install
cd ..
```

### Sign in

Once the browser opens at **http://localhost:5173**:

| | |
|---|---|
| Email | `demo@docutrust.local` |
| Password | `LocalDemoPassword123!` |

Administrator account: `admin@docutrust.local` / `LocalAdminPassword123!`

### Stopping

Close the two windows titled *DocuTrust Backend* and *DocuTrust Frontend*.

---

## Try the demonstration

1. **Upload** → pick `samples\employment-contract-sample.pdf`
2. **Documents** → click the pen icon → **Sign document**
3. Click the download icon to save the signed PDF
4. **Verify** → drag the downloaded file in → green **Authentic document**
5. Alter the signed file:

```powershell
.\scripts\tamper.ps1 "$HOME\Downloads\employment-contract-sample.pdf"
```

6. Open the resulting `-TAMPERED.pdf` in any PDF reader. It looks completely
   normal and now reads 900,000.
7. Drag that file onto **Verify** → red **Tampering detected**

On the red screen, notice that *Document integrity* says **Modified** while
*Certificate* still says **Valid**. That distinction is the point of the
project: the certificate did not change, the document did.

---

## Running the tests

```powershell
cd backend
mvn test
```

60 tests, including a 12-scenario suite that attacks signed documents. The suite
prints a summary of what it observed.

```powershell
cd frontend
npm test
```

23 tests covering status rendering.

---

## Troubleshooting

### "mvn is not recognized" / "java is not recognized"

You are in a terminal that was open before installation. **Close it and open a
new one.** If that does not help, force a refresh in the current window:

```powershell
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
```

### Maven fails with "Could not transfer artifact ... repo.maven.apache.org ... No such host is known"

This happened on the original development machine. The JVM's DNS resolver fails
on Maven Central's default hostname even though the rest of the system resolves
it fine. The fix is to point Maven at `repo1.maven.org`, which is the same
official service under a different name.

Create the file `C:\Users\<YourName>\.m2\settings.xml` containing:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <mirrors>
    <mirror>
      <id>central-repo1</id>
      <name>Maven Central (repo1 hostname)</name>
      <url>https://repo1.maven.org/maven2</url>
      <mirrorOf>central</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

This is a hostname change only — TLS verification and Maven's checksum
validation are untouched.

### "Port 8080 already in use"

An earlier copy of the backend is still running. Find and stop it:

```powershell
Get-NetTCPConnection -LocalPort 8080 -State Listen | Select-Object -ExpandProperty OwningProcess | ForEach-Object { Stop-Process -Id $_ -Force }
```

### "The token '&&' is not a valid statement separator in this version"

You pasted a Command Prompt command into PowerShell. PowerShell 5.1 does not
support `&&`. Either run the commands on separate lines, or use `;` instead.

### "JAVA_HOME is not defined correctly"

```powershell
[Environment]::SetEnvironmentVariable('JAVA_HOME', 'C:\Program Files\Microsoft\jdk-21.0.12.101-hotspot', 'User')
```

Adjust the version number to match what is actually in `C:\Program Files\Microsoft`.
Then open a new terminal.

### The app loads but the documents list is empty

Expected after a restart. The local profile keeps data in memory, so everything
is wiped when the backend stops — and the demo user is recreated with a new
internal identifier, so an old browser session owns nothing. **Sign out and sign
back in.**

### `.\start-docutrust.bat` is blocked or does nothing

Windows sometimes marks files downloaded from the internet as blocked. Right
click the file → **Properties** → tick **Unblock** → OK.

### Frontend shows "Could not reach the DocuTrust server"

The backend is not running or has not finished starting. Check the *DocuTrust
Backend* window for errors, and confirm
http://localhost:8080/actuator/health returns `{"status":"UP"}`.

---

## What gets installed where

| Item | Location |
|---|---|
| Java 21 | `C:\Program Files\Microsoft\jdk-21.*` |
| Maven | `C:\tools\apache-maven-3.9.9` |
| Node.js | `C:\Program Files\nodejs` |
| Maven dependency cache | `C:\Users\<You>\.m2\repository` (~300 MB after first build) |
| Project | wherever you cloned it |

Nothing is installed into the project folder itself except `node_modules` and
`target`, both of which are ignored by Git.

---

## A note on the signing keys

On first run the application generates its own development PKI — a root
certificate authority, an issuing authority and a signer certificate — and says
so loudly in the backend window.

Those keys are real RSA keys, but they exist only in memory and are regenerated
every time the backend restarts. They carry no external trust and must never be
used to sign anything that matters. No key material is stored in the repository.

---

## Useful links once it is running

| | |
|---|---|
| Application | http://localhost:5173 |
| API documentation (Swagger) | http://localhost:8080/swagger-ui.html |
| Health check | http://localhost:8080/actuator/health |
