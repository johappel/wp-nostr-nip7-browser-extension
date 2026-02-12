# view-conversation
dieser Bereich sollte grunsätzlich zusammenklappen uoder unsichtbar sein, ween er nicht im Fokus ist.
also nicht nach oben scollen um zur contact-list zu kommen, sondern die conversation-list sollte sich automatisch zusammenklappen, wenn ein anderes view active gewählt wird.

# message-input 
mehrzeiliges Eingabefeld, damit man auchlängere Nachrichten schreiben kann, ohne dass es unübersichtlich wird. <CTRL+ENTER> sollte eine neue Zeile einfügen und <ENTER> die Nachricht senden.

# message-content
Autolink: Urls sollten automatisch in Links umgewandelt werden

# contact-list
Der eingeloggt User sollte selbst nicht in der Kontaktliste auftauchen, da er sich ja nicht selbst kontaktieren will. 

# PASSKEY: Key aktionen, Schlüsselkopie in Wordpress wird nicht mit dem korrekten Passkey Scope gespeichert:

wemn ich eine Schlüsselkopie in Wordpress speichern will, öffnet sich der Passkey Dialog aber ich finde in chrome nicht wp-norstre-u2-joachim@forums.test-  was korrekt wäre, sondern wp-nostre-global-9412, was vermutem lässt dass der passkey für das Backup auschließlich für den aktuellen User-Scope gespeichert wird.

Es ist sicher zu stellen, dass Passkeys zum Anlegen, Importieren, Exportieren, Speichern, Wiederherstellen und Löschen von Nostr Keys sowie das wechseln der Schutzart an den aktuell in Wordpress eingeloggten User gebunden sind.

Die Anfrage an den Passkey-Dialog sollte zumindest in chrome den Scope `wp-nostr-u2-<username>@<domain>-<rnd>` verwenden. Firefox hat etwas Probleme mit dem Passkey, schau dass du den Code nicht so änderst, dass es dort noch schlechter funktioniert.


ich habe eben gerade einen neien nutzer angelegt. Im wurde angeboten "Mit Nostr Verknüpfen". Nach dem Klick gab es eine Fehlermeldung:

Fehler: Dieser Pubkey ist bereits einem anderen Account zugeordnet.
Verwendeter Signer-Pubkey: f28516909a45...96d1703d
Bitte den richtigen Schluessel fuer diesen WP-User in der Extension waehlen oder importieren.

Das sollte auf keinen Fall Passieren bei einem neuen user, wie kann das Passieren.

Zugehörige Tasks: 10,11,12
