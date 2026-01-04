# 🔐 SMAJS - Surveillance des Mises à Jour de Sécurité

**SMAJS** est un outil léger et puissant pour centraliser la surveillance de la sécurité de vos serveurs Linux. Ne laissez plus vos machines sans correctifs !

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-emerald.svg)](https://github.com/TBDwarf/SMAJS)

---

## 📋 Table des matières
1. [Qu'est-ce que SMAJS ?](#intro)
2. [Pourquoi l'utiliser ?](#why)
3. [Fonctionnalités principales](#features)
4. [Installation](#install)
5. [Configuration](#config)
6. [Utilisation](#usage)
7. [Sécurité](#security)
8. [License](#license)

---

## <a name="intro"></a>🎯 Qu'est-ce que SMAJS ?

**SMAJS** est un script Python automatisé qui se connecte à vos serveurs via SSH pour vérifier leur état de santé. 
Contrairement à une simple commande `apt upgrade`, SMAJS analyse intelligemment la nature des paquets en attente et vous alerte immédiatement si des composants critiques (Kernel, OpenSSL, SSH, etc.) sont vulnérables.

Il génère des rapports détaillés en local et envoie des alertes par email HTML au design moderne et professionnel.

---

## <a name="why"></a>💡 Pourquoi l'utiliser ?

Gérer plusieurs serveurs demande du temps. Il est facile d'oublier une mise à jour de sécurité sur une machine secondaire.

| Critère | Gestion Manuelle | SMAJS |
| :--- | :---: | :---: |
| **Centralisation** | ❌ Non (1 par 1) | ✅ Oui (Multi-machines) |
| **Analyse Critique** | ❌ Non | ✅ Oui (Détection intelligente) |
| **Surveillance Docker** | ❌ Non | ✅ Oui (Images obsolètes) |
| **Alerte Disque** | ❌ Non | ✅ Oui (Seuils configurables) |
| **Rapports Email** | ❌ Non | ✅ Oui (HTML élégant) |

---

## <a name="features"></a>🌟 Fonctionnalités principales

*   **🔍 Multi-Distributions :** Support natif de Debian, Ubuntu, CentOS, RHEL et Fedora.
*   **🚨 Détection Intelligente :** Identification des paquets sensibles (noyau, librairies SSL, services réseau).
*   **🐳 Monitoring Docker :** Analyse des conteneurs en cours et détection des images n'utilisant pas le tag `:latest`.
*   **💽 Santé Disque :** Alerte automatique si une partition dépasse un seuil d'utilisation défini (ex: 90%).
*   **📅 Planification Flexible :** Envoi d'un rapport hebdomadaire systématique OU alertes instantanées en cas de danger critique.
*   **📧 Emailing Premium :** Rapports HTML responsives avec codes couleurs (Rouge = Critique, Vert = OK).

---

## <a name="install"></a>🚀 Installation

### Prérequis
*   Python 3.8+
*   Accès SSH (Username/Password ou Clés) sur les machines cibles.

### Étapes
1. **Cloner le dépôt**
```bash
git clone https://github.com/votre-compte/SMAJS.git
cd SMAJS
```
2. **Installer les dépendances**
SMAJS utilise la bibliothèque `paramiko` pour gérer les connexions SSH de manière sécurisée.
```bash
pip install paramiko
```
3. Configurer les accès
Éditez les fichiers de configuration déjà présents à la racine du projet avec vos propres informations :
```bash
nano config.json
nano machines.json
```
---

## <a name="config"></a>⚙️ Configuration

Le projet repose sur deux fichiers JSON distincts pour séparer la liste de vos serveurs des paramètres globaux du script.

### 1. `machines.json` (Vos serveurs)
Remplissez ce fichier avec les accès SSH de vos machines cibles.
```json
{
  "global_credentials": {
    "username": "admin",
    "password": "votre_password"
  },
  "machines": [
    {
      "name": "Machine 1",
      "ip": "192.168.0.1",
      "username": "admin",
      "password": "votre_password"
    },
    {
      "name": "Machine 2",
      "ip": "192.168.0.2",
      "username": "admin",
      "password": "votre_password"
    }
  ]
}
```
### 2. `config.json` (Paramètres globaux)
Configurez vos alertes et vos paramètres d'envoi d'email (SMTP).
```json
{
  "smtp": {
    "server": "smtp.*.*",
    "port": 465,
    "username": "",
    "password": "",
    "sender": "SMAJS Alerts",
    "recipient": "*@*.*",
    "subject_prefix": "🔐 SMAJS - Rapport de sécurité"
  },
  "rapports": {
    "max_files": 3,
    "dossier": "rapports"
  },
    "securite": {
      "paquets_critiques": [
          "kernel", "openssl", "libssl", "ssh", "sudo", "bash",
          "systemd", "glibc", "nginx", "apache", "httpd",
          "mysql", "mariadb", "postgresql", "php", "python",
          "docker", "kube", "openssh", "firewalld", "iptables",
          "dbus", "pam", "polkit", "cryptsetup", "grub"
    ]
  },
  "planification": {
    "jour_rapport": 4
  },
  "disque": {
    "seuil_alerte": 90
  }
}

```
---

## <a name="usage"></a>📖 Utilisation

Lancez simplement le script pour démarrer une vérification manuelle :
```bash
python3 smajs.py
```
### Automatisation (Cron)
Pour recevoir un rapport automatique tous les matins à 08h00, ajoutez cette ligne à votre `crontab` (`crontab -e`) :
```bash
0 8 * * * /usr/bin/python3 /chemin/vers/votre/projet/smajs.py
```
### 📅 Planification et fréquence des emails

Le script est intelligent : il n'envoie pas d'email inutilement si tout va bien, sauf le jour que vous avez choisi pour le rapport hebdomadaire.

Dans le fichier `config.json`, le paramètre `"jour_rapport"` définit ce comportement :
*   **Alerte Critique ou Disque :** Un email est envoyé **immédiatement** à chaque exécution du script (ex: tous les matins via Cron).
*   **Rapport de routine :** Si aucune alerte n'est détectée, le script attend le jour configuré pour envoyer un rapport de santé global.

**Valeurs pour `"jour_rapport"` :**
*   `0` = Lundi
*   `1` = Mardi
*   `2` = Mercredi
*   `3` = Jeudi
*   **`4` = Vendredi** (par défaut)
*   `5` = Samedi
*   `6` = Dimanche

> **Exemple :** Avec le réglage par défaut (`4`), si vous lancez le script via Cron tous les jours, vous recevrez des alertes instantanées en cas de danger, et un rapport complet de routine chaque vendredi matin.
---

## <a name="security"></a>🔒 Sécurité

*   **Audit passif :** Le script n'effectue que des commandes de lecture (`apt list`, `df`, `docker ps`). Il ne modifie jamais vos systèmes.
*   **Gestion des accès :** Il est recommandé d'utiliser un utilisateur avec des droits restreints sur les machines distantes.
*   **Confidentialité :** Aucune donnée n'est envoyée vers des serveurs tiers. Les rapports transitent uniquement entre vos serveurs et votre propre serveur SMTP.

---

## <a name="license"></a>📜 License

Ce projet est distribué sous la **Apache License, Version 2.0**.

Voir le fichier [LICENSE](LICENSE) pour plus de détails.

```
Copyright 2025 TBDwarf

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## 📞 Contact

- **GitHub Issues :** [https://github.com/TBDwarf/SMAJS/issues](https://github.com/TBDwarf/SMAJS/issues)

---

<div align="center">

**Fait avec 🔐 et ❤️ en France**

⭐ Si SMAJS vous est utile, pensez à **mettre une étoile** sur GitHub ! ⭐

</div>
