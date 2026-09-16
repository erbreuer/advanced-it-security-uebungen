# Password Pages – Dokumentation

## Ziel

Das Passwort der geschützten Datei `Passwords.pages` sollte anhand des enthaltenen Passwort-Hinweises ermittelt werden.

## 1. `.pages`-Datei als ZIP-Datei behandeln

Eine `.pages`-Datei ist technisch eine ZIP-Datei. Der Hash wurde mit `iwork2john` extrahiert:

```bash
python3 ~/john/run/iwork2john.py Passwords.pages > hash.txt
```

Dabei wurde folgender Passwort-Hinweis ausgegeben:

```text
My name is: #j***j***1
```

Die Hash-Datei enthielt beispielsweise:

```text
Passwords.pages:$iwork$1$2$1$100000$...::::My name is: #j***j***1 Passwords.pages
```

## 2. Hash für Hashcat aufbereiten

Für Hashcat müssen Dateiname und Passwort-Hinweis entfernt werden:

```bash
sed 's/::::.*//; s/^[^:]*://' hash.txt > hashcat.txt
```

Danach enthält `hashcat.txt` ausschließlich den iWork-Hash.

## 3. Passwortmuster ableiten

Der Hinweis

```text
#j***j***1
```

entspricht folgendem Schema:

```text
#<vierbuchstabiger Name mit j><vierbuchstabiger Name mit j>1
```

Beispiel:

```text
#janejudy1
```

Als Wortliste wurde eine Datei mit kleingeschriebenen, vierbuchstabigen Namen verwendet, die mit `j` beginnen (von KI erstellt):

```text
j_namen_4zeichen_nur_klein.txt
```

## 4. Kreuzprodukt mit Hashcat erzeugen

Der Kombinator-Angriff (`-a 1`) verbindet jeden Namen der ersten Liste mit jedem Namen der zweiten Liste.

```bash
hashcat -m 23300 hashcat.txt -a 1 \
  -j '^#' -k '$1' \
  j_namen_4zeichen_nur_klein.txt \
  j_namen_4zeichen_nur_klein.txt
```

### Verwendete Optionen

| Option | Bedeutung |
|---|---|
| `-m 23300` | Hash-Modus für Apple iWork |
| `-a 1` | Kombinator-Angriff / Kreuzprodukt zweier Wortlisten |
| `-j '^#'` | Fügt `#` vor dem linken Namen ein |
| `-k '$1'` | Fügt `1` an den rechten Namen an |

Dadurch entstehen Kandidaten im Muster:

```text
#name1name21
```

## Ergebnis

Das Passwort wurde erfolgreich ermittelt:

```text
#janejudy1
```