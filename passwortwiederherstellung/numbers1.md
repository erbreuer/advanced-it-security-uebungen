# Numbers1 – Passwort-Dokumentation

## 1. Hash extrahieren

Da es sich bei `Numbers1.odt` um eine LibreOffice-Datei handelt, wurde `libreoffice2john` verwendet.

Der Hash wurde extrahiert und für Hashcat aufbereitet:

```bash
python3 ~/john/run/libreoffice2john.py Numbers1.odt | \
sed -E -e 's/[^:]+://' -e 's/:::::[^:]+$//' \
> number_1/Numbers1.odt.hashcat
```

## 2. Hashcat-Modus bestimmen

Der extrahierte Hash wurde mit `cat` angesehen und mit den Beispiel-Hashes auf der Hashcat-Webseite verglichen (es gibt viele Möglichkeiten den Hash zu identifizieren):

```text
https://hashcat.net/wiki/doku.php?id=example_hashes
```

Der passende Hashcat-Modus lautet:

```text
18400
```

## 3. Wörterbuchangriff durchführen

Als erster Versuch wurde die Wortliste `rockyou.txt` verwendet:

```bash
hashcat -a 0 -m 18400 Numbers1.odt.hashcat rockyou.txt
```

Der Angriff war erfolgreich.

## 4. Passwort anzeigen

Das gefundene Passwort kann mit folgendem Befehl angezeigt werden:

```bash
hashcat -m 18400 Numbers1.odt.hashcat --show
```

Ausgabe:

```text
[...]ddc51688171dc904f2fbb4a5bc94afec6cbd786faa2e044e78245396306ae8da49e1aab2ab3edbc32893c6dd37828d8363ebe283d2a8051f9:1234abcd
```

## Ergebnis

Das Passwort steht hinter dem Doppelpunkt:

```text
1234abcd
```