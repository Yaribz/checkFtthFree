# checkFtthFree
Programme de diagnostic de connexion FTTH Free

Ce programme analyse la configuration réseau du système et effectue différents
tests TCP (latence et débit mono-connexion) afin d'évaluer les performances de
la connexion FTTH et détecter d'éventuels dysfonctionnements.
Diverses options sont disponibles pour configurer ou désactiver certains tests,
voir --help (-h) pour plus d'information.

Usage:

    checkFtthFree.pl [<options>]
        --ipv6 (-6) : Effectue les tests Internet en IPv6 (IPv4 par défaut)
        --alternate-srv (-a) : Change de serveurs pour les tests Internet (utilise l'AS 5410 "Bouygues Telecom" à la place de l'AS 12876 "Scaleway")
        --binary-units (-b) : Utilise les préfixes binaires pour le système d'unités de débit
        --check-update (-c) : Effectue seulement la vérification de disponibilité de nouvelle version
        --skip-check-update (-C) : Désactive la vérification de disponibilité de nouvelle version
        --extended-test (-e) : Effectue des tests plus longs (multiplie par 2 la durée max des tests)
        --freebox (-f) : Effectue seulement les tests locaux à partir de la Freebox (pas de test Internet)
        --skip-freebox (-F) : Désactive les tests locaux à partir de la Freebox (tests Internet uniquement, empêche la détection de certains problèmes)
        --help (-h) : Affiche l'aide
        --skip-intro (-I) : Désactive le message d'introduction et démarre immédiatement les tests
        --latency (-l) : Effectue seulement les tests de latence (pas de test de débit)
        --skip-latency (-L) : Désactive les tests de latence (tests de débit uniquement, empêche la détection de certains problèmes)
        --net-conf (-n) : Effectue seulement la lecture de la configuration réseau
        --skip-net-conf (-N) : Désactive la lecture de la configuration réseau (empêche la détection de certains problèmes)
        --quiet (-q) : Mode silencieux: désactive les messages d'analyse et d'avertissement
        --suggestions (-s) : Affiche des suggestions pour résoudre des problèmes de configuration réseau ou compléter les tests si besoin
        --upload (-u) : Effectue un test de débit montant au lieu de descendant (EXPERIMENTAL)
        --version (-v) : Affiche la version
