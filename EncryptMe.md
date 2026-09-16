# Reverse Engineering von `EncryptMe` – Entschlüsselung von `Image.png.encrypted`

## 1. Ziel

Ziel der Aufgabe war es, die mit `encryptme` verschlüsselte Datei `Image.png.encrypted` ohne bekanntes Passwort zu entschlüsseln.

Verwendet wurde die x86-64-Version:

```text
encryptme-x86-64
```

und die verschlüsselte Datei:

```text
Image.png.encrypted
```

---

## 2. Binary untersuchen

Zuerst wurde der Dateityp des Programms überprüft:

```bash
file encryptme-x86-64
```

**Bedeutung:** `file` bestimmt den Typ und wichtige Eigenschaften einer Datei.

Ergebnis:

```text
ELF 64-bit LSB pie executable, x86-64
```

Außerdem war das Binary **nicht gestripped** und enthielt Debug-Informationen. Dadurch waren Funktionsnamen noch vorhanden.

Anschließend wurden die vorhandenen Funktionen angezeigt:

```bash
nm -C encryptme-x86-64 | grep ' T '
```

**Bedeutung:** `nm` listet Symbole eines Binaries auf. Mit `grep ' T '` wurden die Funktionen im Code-Bereich herausgefiltert.

Interessante Funktionen waren:

```text
main
password_to_seed
rng_init
rng_next
xor_crypt
```

Diese Funktionen waren besonders relevant für die Rekonstruktion der Verschlüsselung.

---

## 3. Unterstützte Modi untersuchen

Die im Binary enthaltenen Strings wurden untersucht:

```bash
strings -tx encryptme-x86-64 | grep -E '2071|2079'
```

**Bedeutung:** `strings` sucht lesbare Zeichenketten im Binary. `-t x` zeigt zusätzlich die Adresse in hexadezimaler Form.

Ergebnis:

```text
2071 encrypt
2079 decrypt
```

Damit war klar, dass das Programm unter anderem mit dem Modus `decrypt` gestartet werden kann.

---

## 4. `password_to_seed` analysieren

Die Funktion `password_to_seed` wurde anschließend disassembliert. Daraus konnte folgende Logik rekonstruiert werden:

```c
uint64_t password_to_seed(const char *password)
{
    uint64_t seed = 0x1505;

    int i = 0;

    while (password[i] != '\0')
    {
        seed = seed * 33 + (unsigned char)password[i];
        i++;
    }

    return seed;
}
```

Das Passwort wird also zunächst in einen Seed umgewandelt.

Wichtig war anschließend die Verwendung dieses Seeds in `main`:

```c
seed = password_to_seed(password);
rng_init(seed & 0xFFFFFF);
```

Es werden also nur die unteren **24 Bit** des berechneten Seeds verwendet.

---

## 5. Zufallszahlengenerator analysieren

Die Funktion `rng_init` initialisiert den Zustand des Generators:

```c
uint64_t *rng_init(uint64_t seed)
{
    uint64_t *rng = malloc(8);
    *rng = seed;
    return rng;
}
```

Die eigentliche Berechnung findet in `rng_next` statt:

```c
uint32_t rng_next(uint64_t *state)
{
    *state = (*state * 0x41C64E6D + 0x3039) & 0x7FFFFFFF;

    return *state >> 8;
}
```

Der Zustand wird bei jedem Byte nach folgendem Schema aktualisiert:

```text
state = (state * 0x41C64E6D + 0x3039) & 0x7FFFFFFF
```

---

## 6. XOR-Verschlüsselung analysieren

Die Funktion `xor_crypt` wurde ebenfalls untersucht:

```c
void xor_crypt(unsigned char *data, int length, uint64_t *rng)
{
    for (int i = 0; i < length; i++)
    {
        uint32_t key = rng_next(rng);
        data[i] ^= key;
    }
}
```

Entscheidend ist:

```c
data[i] ^= key;
```

Die Datei wird Byte für Byte mit einem aus dem PRNG erzeugten Wert per XOR verarbeitet.

Da `data[i]` nur ein Byte groß ist, ist effektiv das unterste Byte des Keys relevant:

```c
uint8_t key = (rng_next(rng) & 0xff);
```

XOR ist symmetrisch:

```text
Klartext XOR Key      = Ciphertext
Ciphertext XOR Key    = Klartext
```

Daher kann derselbe Keystream zum Entschlüsseln verwendet werden.

---

# 7. Verschlüsselte Datei untersuchen

Die Größe der verschlüsselten Datei wurde überprüft:

```bash
ls -lh Image.png.encrypted
```

Ergebnis:

```text
-rw------- ... 2.4M ... Image.png.encrypted
```

Anschließend wurden die ersten 32 Bytes untersucht:

```bash
xxd -l 32 Image.png.encrypted
```

Ergebnis:

```text
00000000: 371d 62ed 5647 1690 9c60 67b6 69ba 7e0a
00000010: 412e 467e 1c01 f3f9 8514 9954 3073 30d8
```

Da die Datei verschlüsselt ist, konnte sie mit:

```bash
file Image.png.encrypted
```

nicht als PNG erkannt werden:

```text
Image.png.encrypted: data
```

---

# 8. Bekannten PNG-Header ausnutzen

Eine PNG-Datei besitzt einen bekannten Dateianfang:

```text
89 50 4e 47 0d 0a 1a 0a
```

Der Ciphertext beginnt dagegen mit:

```text
37 1d 62 ed 56 47 16 90
```

Da gilt:

```text
Ciphertext = Klartext XOR Key
```

kann man den Keystream berechnen:

```text
Key = Ciphertext XOR Klartext
```

Also:

```text
37 1d 62 ed 56 47 16 90
XOR
89 50 4e 47 0d 0a 1a 0a
=
be 4d 2c aa 5b 4d 0c 9a
```

Damit waren die ersten 8 Bytes des benötigten Keystreams bekannt.

---

# 9. Seed brute-forcen

Da nur 24 Bit des Passwort-Seeds verwendet werden, gibt es maximal:

```text
2^24 = 16.777.216
```

mögliche Seeds.

Es wurde deshalb ein C-Programm `find_seed.c` geschrieben, das alle möglichen Seeds ausprobiert.

### `find_seed.c`

```c
#include <stdio.h>
#include <stdint.h>

int main(void)
{
    const uint8_t expected[] = {
        0xbe, 0x4d, 0x2c, 0xaa,
        0x5b, 0x4d, 0x0c, 0x9a
    };

    for (uint32_t seed = 0; seed < 0x1000000; seed++)
    {
        uint32_t state = seed;
        int match = 1;

        for (int i = 0; i < 8; i++)
        {
            state = (state * 0x41C64E6D + 0x3039)
                    & 0x7FFFFFFF;

            uint8_t output = (state >> 8) & 0xff;

            if (output != expected[i])
            {
                match = 0;
                break;
            }
        }

        if (match)
        {
            printf("Seed gefunden: 0x%06x (%u)\n",
                   seed, seed);
        }
    }

    return 0;
}
```

Das Programm wurde kompiliert:

```bash
gcc -O3 find_seed.c -o find_seed
```

**Bedeutung:** `gcc` kompiliert den C-Code. `-O3` aktiviert Optimierungen und `-o find_seed` legt den Namen der ausführbaren Datei fest.

Danach wurde der Brute-Force-Angriff gestartet:

```bash
./find_seed
```

Es wurden 256 passende Seeds gefunden.

Sie hatten alle das Muster:

```text
0x??5fce
```

Beispielsweise:

```text
0x005fce
0x015fce
0x025fce
...
0xff5fce
```

---

# 10. Gefundene Schwachstelle

Hier liegt die wichtigste Schwachstelle von `EncryptMe`.

Obwohl zunächst 24 Bit des Seeds verwendet werden:

```c
seed & 0xFFFFFF
```

wird der PRNG anschließend so verwendet:

```c
return *state >> 8;
```

und davon wird beim XOR mit einem einzelnen Byte letztendlich nur das unterste Byte verwendet:

```c
(state >> 8) & 0xff
```

Damit sind für den tatsächlichen Byte-Keystream nur bestimmte Bits des PRNG-Zustands relevant.

Die oberen 8 Bit des ursprünglichen 24-Bit-Seeds können den erzeugten Byte-Keystream nicht unterscheiden.

Deshalb erzeugen:

```text
0x005fce
0x015fce
0x025fce
...
0xff5fce
```

denselben relevanten Keystream.

Der effektive Suchraum reduziert sich dadurch von:

```text
2^24 = 16.777.216
```

auf:

```text
2^16 = 65.536
```

relevante Zustände.

---

# 11. Warum die Schwachstelle ausnutzbar ist

Ein Angreifer benötigt das ursprüngliche Passwort nicht zwingend.

Es reichen:

1. Ein bekanntes Stück Klartext.
2. Der dazugehörige Ciphertext.
3. Die Kenntnis des Verschlüsselungsalgorithmus.
4. Ein ausreichend kleiner Seed-Suchraum.

Bei einer PNG-Datei ist Punkt 1 besonders einfach, weil der Dateityp einen standardisierten Header besitzt.

Der Angriff funktioniert somit:

```text
PNG-Header bekannt
       ↓
Ciphertext des Headers bekannt
       ↓
Ciphertext XOR PNG-Header
       ↓
Keystream bekannt
       ↓
Seeds brute-forcen
       ↓
passender Seed gefunden
       ↓
PRNG rekonstruieren
       ↓
gesamten Keystream erzeugen
       ↓
gesamte Datei entschlüsseln
```

Ein wichtiger Punkt ist dabei:

> Man muss nicht das Passwort brechen, um die Datei zu entschlüsseln. Es reicht, den für den Verschlüsselungsalgorithmus relevanten PRNG-Zustand zu finden.

Das ist ein wesentlicher Unterschied zwischen **Passwort-Recovery** und **Entschlüsselung**.

---

# 12. Entschlüsselungsprogramm

Nachdem `0x5fce` als relevanter Seed-Anteil gefunden wurde, konnte die Datei direkt entschlüsselt werden.

Dafür wurde `decrypt.c` erstellt:

```c
#include <stdio.h>
#include <stdint.h>

int main(void)
{
    FILE *in = fopen("Image.png.encrypted", "rb");
    FILE *out = fopen("Image.png", "wb");

    if (in == NULL || out == NULL)
    {
        perror("Fehler beim Öffnen der Datei");
        return 1;
    }

    uint32_t state = 0x5fce;

    int c;

    while ((c = fgetc(in)) != EOF)
    {
        state = (state * 0x41C64E6D + 0x3039)
                & 0x7FFFFFFF;

        uint8_t key = (state >> 8) & 0xff;

        uint8_t decrypted = (uint8_t)c ^ key;

        fputc(decrypted, out);
    }

    fclose(in);
    fclose(out);

    printf("Entschlüsselung erfolgreich.\n");
    printf("Ausgabe: Image.png\n");

    return 0;
}
```

Das Programm wurde kompiliert:

```bash
gcc -O3 decrypt.c -o decrypt
```

Danach wurde die Datei entschlüsselt:

```bash
./decrypt
```

Dabei wurde:

```text
Image.png.encrypted
```

eingelesen und:

```text
Image.png
```

erzeugt.

---

# 13. Ergebnis überprüfen

Der Dateityp wurde anschließend erneut überprüft:

```bash
file Image.png
```

Das Ergebnis:

```text
Image.png: PNG image data, 1536 x 1024, 8-bit/color RGB, non-interlaced
```

Damit wurde bestätigt, dass die Entschlüsselung erfolgreich war.

Zusätzlich kann der PNG-Header kontrolliert werden:

```bash
xxd -l 32 Image.png
```

Die ersten Bytes sollten mit:

```text
89 50 4e 47 0d 0a 1a 0a
```

beginnen.

Das ist die typische PNG-Signatur.

---

# 14. Entschlüsseltes Bild öffnen

Unter einer Linux-GUI kann das Bild mit:

```bash
xdg-open Image.png
```

geöffnet werden.

**Bedeutung:** `xdg-open` öffnet die Datei mit dem im System eingestellten Standardprogramm für PNG-Dateien.

Alternativ kann unter Ubuntu beispielsweise verwendet werden:

```bash
eog Image.png
```

**Bedeutung:** `eog` öffnet die Datei mit dem GNOME-Bildbetrachter.

---

# 15. Komplette Befehlsübersicht

Die wichtigsten während der Analyse verwendeten Befehle in chronologischer Reihenfolge:

```bash
file encryptme-x86-64
```

→ Eigenschaften und Dateityp des Binaries anzeigen.

```bash
nm -C encryptme-x86-64 | grep ' T '
```

→ Funktionen/Symbole des nicht gestripped Binaries anzeigen.

```bash
strings -tx encryptme-x86-64 | grep -E '2071|2079'
```

→ Nach den Strings `encrypt` und `decrypt` suchen.

```bash
ls -lh Image.png.encrypted
```

→ Größe und Dateiinformationen anzeigen.

```bash
xxd -l 32 Image.png.encrypted
```

→ Erste 32 Bytes des verschlüsselten Files anzeigen.

```bash
file Image.png.encrypted
```

→ Dateityp des verschlüsselten Files überprüfen.

```bash
gcc -O3 find_seed.c -o find_seed
```

→ Seed-Brute-Force-Programm kompilieren.

```bash
./find_seed
```

→ Alle möglichen 24-Bit-Seeds testen.

```bash
gcc -O3 decrypt.c -o decrypt
```

→ Eigenes Entschlüsselungsprogramm kompilieren.

```bash
./decrypt
```

→ `Image.png.encrypted` mit dem gefundenen effektiven Seed entschlüsseln.

```bash
file Image.png
```

→ Überprüfen, ob das Ergebnis tatsächlich eine PNG-Datei ist.

```bash
xxd -l 32 Image.png
```

→ PNG-Header der entschlüsselten Datei überprüfen.

```bash
xdg-open Image.png
```

→ Entschlüsseltes Bild im Standard-Bildbetrachter öffnen.

---

# 16. Fazit

Die Datei konnte ohne Kenntnis des ursprünglichen Passworts entschlüsselt werden.

Der entscheidende Angriff beruhte auf der Kombination aus:

* bekanntem PNG-Header,
* XOR-Verschlüsselung,
* deterministischem PRNG,
* lediglich 24 Bit Seed,
* effektiv nur 16 relevanten Seed-Bits,
* und fehlender Verwendung eines kryptografisch sicheren Schlüsselableitungsverfahrens.

Der aus dem PNG-Header abgeleitete Keystream ermöglichte es, den effektiven Seed `0x5fce` durch Brute-Force zu finden.

Anschließend konnte mit demselben rekonstruierten PRNG der vollständige Keystream erzeugt und die gesamte Datei entschlüsselt werden.

Das ursprüngliche Passwort wurde dabei **nicht rekonstruiert**. Stattdessen wurde direkt der für die Verschlüsselung relevante Zustand des PRNG bestimmt.

Das Ergebnis war eine gültige:

```text
PNG image data, 1536 x 1024, 8-bit/color RGB, non-interlaced
```

Datei.
