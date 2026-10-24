@echo off
setlocal

REM ---------------------------------------------------------------------------
REM  DocuTrust - start everything and open the browser.
REM
REM  Double-click this file, or run it from Command Prompt.
REM
REM  It opens two windows (backend and frontend), waits until the backend is
REM  actually answering, then opens the app in your default browser.
REM
REM  Close those two windows to stop the application.
REM ---------------------------------------------------------------------------

set "PROJECT=%~dp0"
set "PROJECT=%PROJECT:~0,-1%"

REM --- Development credentials -----------------------------------------------
REM  These are local demonstration values only. Without them the application
REM  generates random ones at startup and prints them to the backend window.
set "DOCUTRUST_JWT_SECRET=local-development-only-secret-value-at-least-32-bytes-long-xyz"
set "DOCUTRUST_DEMO_USER_PASSWORD=LocalDemoPassword123!"
set "DOCUTRUST_DEMO_ADMIN_PASSWORD=LocalAdminPassword123!"

echo.
echo ==================================================================
echo   DocuTrust
echo ==================================================================
echo.

REM --- Refuse to start twice --------------------------------------------------
netstat -ano | findstr /R /C:":8080 .*LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo   Port 8080 is already in use - the backend is probably running.
    echo   Opening the browser instead.
    echo.
    start "" http://localhost:5173
    goto :done
)

echo   Starting backend  ... a new window will open
start "DocuTrust Backend" cmd /k "cd /d "%PROJECT%\backend" && mvn spring-boot:run"

echo   Starting frontend ... a new window will open
start "DocuTrust Frontend" cmd /k "cd /d "%PROJECT%\frontend" && npm run dev"

echo.
echo   Waiting for the backend to finish starting.
echo   This usually takes 20 to 40 seconds.
echo.

set /a ATTEMPTS=0

:wait
set /a ATTEMPTS+=1
if %ATTEMPTS% gtr 60 goto :timeout

timeout /t 2 /nobreak >nul
curl -s -o nul -m 2 http://localhost:8080/actuator/health
if errorlevel 1 (
    echo   ... still starting  [%ATTEMPTS%]
    goto :wait
)

echo.
echo ==================================================================
echo   READY
echo ==================================================================
echo.
echo   Application : http://localhost:5173
echo   API docs    : http://localhost:8080/swagger-ui.html
echo.
echo   Sign in with:
echo     demo@docutrust.local  /  LocalDemoPassword123!
echo.
echo   Leave the two other windows open. Closing them stops the app.
echo ==================================================================
echo.

start "" http://localhost:5173
goto :done

:timeout
echo.
echo   The backend did not start within two minutes.
echo   Check the "DocuTrust Backend" window for an error message.
echo.

:done
echo   Press any key to close this window.
pause >nul
endlocal