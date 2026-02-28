#!/usr/bin/env python3
"""
SMAJS - Surveillance des Mises à Jour de Sécurité
V2.2 by TBDwarf
"""

import paramiko
import socket
import time
import json
import os
import sys
import re
import smtplib
from typing import List, Dict, Tuple, Any
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.utils import formatdate
from email import encoders
import glob

class SMASJPro:
    def __init__(self, config_file: str = "config.json", machines_file: str = "machines.json"):
        """
        Initialise le système SMAJS Pro
        """
        self.config = self._load_config(config_file)
        self.machines = self._load_machines(machines_file)
        self.results = {}

        # Paramètre global pour le seuil disque (par défaut 80 si non présent)
        self.disk_threshold = (
            self.config.get("disque", {}).get("seuil_alerte", 80)
        )

        # Créer le dossier des rapports si nécessaire
        self.report_dir = self.config["rapports"]["dossier"]
        os.makedirs(self.report_dir, exist_ok=True)

    def _load_config(self, config_file: str) -> Dict:
        """
        Charge la configuration depuis config.json
        """
        if not os.path.exists(config_file):
            self._create_default_config(config_file)
            sys.exit(1)

        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"❌ ERREUR: Fichier JSON invalide - {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ ERREUR: {e}")
            sys.exit(1)

    def _create_default_config(self, config_file: str):
        """
        Crée un fichier de configuration par défaut
        """
        default_config = {
            "smtp": {
                "server": "smtp.gmail.com",
                "port": 465,
                "username": "votre_email@gmail.com",
                "password": "votre_mot_de_passe_app",
                "sender": "SMAJS Alerts <votre_email@gmail.com>",
                "recipient": "destinataire@example.com",
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
                "jour_rapport": 4  # 0=lundi ... 4=vendredi ; utilisé si pas de critiques
            },
            "disque": {
                "seuil_alerte": 80  # en %, au-delà de ce seuil d'utilisation -> alerte
            }
        }

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)

        print(f"✅ Fichier de configuration créé : {config_file}")
        print("⚠️  Modifiez-le avec vos paramètres SMTP avant de relancer !")

    def _load_machines(self, machines_file: str) -> List[Dict]:
        """
        Charge la configuration des machines
        """
        if not os.path.exists(machines_file):
            print(f"❌ Fichier {machines_file} introuvable !")
            sys.exit(1)

        try:
            with open(machines_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get("machines", [])
        except Exception as e:
            print(f"❌ Erreur lors du chargement des machines: {e}")
            sys.exit(1)

    def _clean_old_reports(self):
        """
        Nettoie les anciens rapports pour ne garder que les X plus récents
        """
        max_files = self.config["rapports"]["max_files"]
        pattern = os.path.join(self.report_dir, "rapport_smajs_*.txt")
        files = glob.glob(pattern)

        if len(files) > max_files:
            # Trier par date de modification (du plus ancien au plus récent)
            files.sort(key=os.path.getmtime)

            # Supprimer les plus anciens
            for file in files[:-max_files]:
                try:
                    os.remove(file)
                    print(f"🗑️  Supprimé: {os.path.basename(file)}")
                except Exception as e:
                    print(f"⚠️  Impossible de supprimer {file}: {e}")

    def _get_credentials(self, machine: Dict) -> Tuple[str, str]:
        """
        Récupère les credentials pour une machine
        """
        username = machine.get("username")
        password = machine.get("password")

        if not username or not password:
            return None, None

        return username, password

    def _check_docker(self, ssh, password: str | None) -> Dict[str, Any]:
        """
        Vérifie la présence de Docker et donne une info très légère sur les images.
        """
        result = {
            "has_docker": False,
            "error": None,
            "containers": 0,
            "images_total": 0,
            "images_outdated": 0,
            "outdated_images": [],
        }

        def parse_docker_ps_output(raw: str) -> Tuple[int, int, list]:
            """Parse la sortie 'nom;;image' en (nb_containers, nb_images, liste_images)."""
            lines = [l for l in raw.split("\n") if l.strip()]
            containers = []
            images = set()
            for line in lines:
                parts = line.split(";;")
                if len(parts) != 2:
                    continue
                cname, cimage = parts
                cname = cname.strip()
                cimage = cimage.strip()
                if not cname and not cimage:
                    continue
                containers.append((cname, cimage))
                if cimage:
                    images.add(cimage)
            return len(containers), len(images), sorted(images)

        try:
            # 1) Vérifier si docker est installé
            stdin, stdout, stderr = ssh.exec_command(
                "command -v docker >/dev/null 2>&1 && echo 'yes' || echo 'no'"
            )
            has_docker_raw = stdout.read().decode().strip()

            if has_docker_raw != "yes":
                return result  # pas de docker installé

            result["has_docker"] = True

            # 2) Essayer docker ps sans sudo
            cmd = "docker ps --format '{{.Names}};;{{.Image}}' 2>&1"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            out = stdout.read().decode()
            err = stderr.read().decode()
            combined = (out + "\n" + err).lower()

            need_sudo = "permission denied" in combined or "got permission denied" in combined

            if not need_sudo and ("cannot connect to the docker daemon" in combined and "permission denied" not in combined):
                result["error"] = (out + "\n" + err).strip() or "Erreur lors de l'accès à Docker (daemon indisponible)."
                return result

            if not need_sudo and out.strip():
                containers, nb_images, images = parse_docker_ps_output(out)
                result["containers"] = containers
                result["images_total"] = nb_images
            elif need_sudo:
                if not password:
                    result["error"] = "Permission refusée pour Docker et aucun mot de passe sudo disponible."
                    return result

                sudo_cmd = "sudo -S -p '' docker ps --format '{{.Names}};;{{.Image}}' 2>&1"
                stdin, stdout, stderr = ssh.exec_command(sudo_cmd)
                stdin.write(password + "\n")
                stdin.flush()

                out_sudo = stdout.read().decode()
                err_sudo = stderr.read().decode()
                combined_sudo = (out_sudo + "\n" + err_sudo).lower()

                if "permission denied" in combined_sudo or "authentication failure" in combined_sudo:
                    result["error"] = "Permission refusée pour accéder à Docker (sudo). Vérifier sudoers / droits."
                    return result

                if "cannot connect to the docker daemon" in combined_sudo and "permission denied" not in combined_sudo:
                    result["error"] = (out_sudo + "\n" + err_sudo).strip() or "Erreur lors de l'accès à Docker (daemon indisponible via sudo)."
                    return result

                if out_sudo.strip():
                    containers, nb_images, images = parse_docker_ps_output(out_sudo)
                    result["containers"] = containers
                    result["images_total"] = nb_images
                else:
                    return result
            else:
                return result

            if result["images_total"] == 0:
                return result

            images_set = set()

            if need_sudo:
                sudo_cmd2 = "sudo -S -p '' docker ps --format '{{.Image}}'"
                stdin2, stdout2, stderr2 = ssh.exec_command(sudo_cmd2)
                stdin2.write(password + "\n")
                stdin2.flush()
                imgs_raw = stdout2.read().decode().strip().split("\n")
            else:
                stdin2, stdout2, stderr2 = ssh.exec_command("docker ps --format '{{.Image}}'")
                imgs_raw = stdout2.read().decode().strip().split("\n")

            for img in imgs_raw:
                img = img.strip()
                if img:
                    images_set.add(img)

            if not images_set:
                return result

            IGNORE_DOCKER_IMAGES = {
                "mongo:4.4.18",
            }

            outdated = []
            for img in images_set:
                if img in IGNORE_DOCKER_IMAGES:
                    continue

                if ":" in img:
                    repo, tag = img.rsplit(":", 1)
                else:
                    repo, tag = img, "latest"

                if tag != "latest":
                    outdated.append(img)

            result["outdated_images"] = sorted(outdated)
            result["images_outdated"] = len(outdated)

        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_disk(self, ssh, threshold: int = None) -> Dict[str, Any]:
        """
        Vérifie l'utilisation disque.
        Alerte si une partition dépasse 'threshold' % d'utilisation.
        Si threshold est None, utilise self.disk_threshold.
        """
        if threshold is None:
            threshold = self.disk_threshold

        result = {
            "alert": False,
            "threshold": threshold,
            "partitions": [],
            "error": None
        }

        try:
            cmd = "df -P -h 2>/dev/null"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode().strip()
            err = stderr.read().decode().strip()

            if not output:
                result["error"] = err or "Aucune sortie de 'df'."
                return result

            lines = output.splitlines()
            if len(lines) <= 1:
                result["error"] = "Sortie de 'df' invalide ou incomplète."
                return result

            # Première ligne = header
            for line in lines[1:]:
                parts = line.split()
                # FS  size  used  avail  use%  mountpoint
                if len(parts) < 6:
                    continue

                filesystem = parts[0]
                pcent = parts[4]
                mountpoint = parts[5]

                if filesystem.startswith("tmpfs") or filesystem.startswith("devtmpfs"):
                    continue

                try:
                    used_percent = int(pcent.strip().replace("%", ""))
                except ValueError:
                    continue

                if used_percent >= threshold:
                    result["alert"] = True
                    result["partitions"].append({
                        "filesystem": filesystem,
                        "mountpoint": mountpoint,
                        "used_percent": used_percent
                    })

        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_machine(self, machine: Dict) -> Dict[str, Any]:
        """
        Vérifie une machine et retourne les résultats
        """
        name = machine["name"]
        ip = machine["ip"]

        username, password = self._get_credentials(machine)

        if not username or not password:
            return {
                "name": name,
                "ip": ip,
                "status": "error",
                "error": "Identifiants manquants",
                "distribution": "Inconnue",
                "updates": {
                    "total": 0,
                    "critical": 0,
                    "security": 0,
                    "regular": 0
                },
                "packages": {
                    "critical": [],
                    "security": [],
                    "regular": []
                },
                "docker": {
                    "has_docker": False,
                    "error": None,
                    "containers": 0,
                    "images_total": 0,
                    "images_outdated": 0,
                    "outdated_images": []
                },
                "disk": {
                    "alert": False,
                    "threshold": self.disk_threshold,
                    "partitions": [],
                    "error": "Vérification impossible (identifiants manquants)."
                }
            }

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(ip, username=username, password=password,
                       timeout=10, banner_timeout=10)

            distro = self._detect_distribution(ssh)

            if distro in ["ubuntu", "debian"]:
                base_result = self._check_apt(ssh, name, ip, distro)
            elif distro in ["centos", "rhel"]:
                base_result = self._check_yum(ssh, name, ip, distro)
            elif distro == "fedora":
                base_result = self._check_dnf(ssh, name, ip, distro)
            else:
                base_result = {
                    "name": name,
                    "ip": ip,
                    "status": "warning",
                    "error": f"Distribution non supportée: {distro}",
                    "distribution": distro,
                    "updates": {"total": 0, "critical": 0, "security": 0, "regular": 0},
                    "packages": {"critical": [], "security": [], "regular": []}
                }

            docker_info = self._check_docker(ssh, password)
            base_result["docker"] = docker_info

            disk_info = self._check_disk(ssh, threshold=self.disk_threshold)
            base_result["disk"] = disk_info

            return base_result

        except paramiko.AuthenticationException:
            return {
                "name": name,
                "ip": ip,
                "status": "error",
                "error": "Échec d'authentification SSH",
                "distribution": "Inconnue",
                "updates": {"total": 0, "critical": 0, "security": 0, "regular": 0},
                "packages": {"critical": [], "security": [], "regular": []},
                "docker": {
                    "has_docker": False,
                    "error": None,
                    "containers": 0,
                    "images_total": 0,
                    "images_outdated": 0,
                    "outdated_images": []
                },
                "disk": {
                    "alert": False,
                    "threshold": self.disk_threshold,
                    "partitions": [],
                    "error": "Vérification impossible (authentification SSH échouée)."
                }
            }
        except Exception as e:
            return {
                "name": name,
                "ip": ip,
                "status": "error",
                "error": str(e),
                "distribution": "Inconnue",
                "updates": {"total": 0, "critical": 0, "security": 0, "regular": 0},
                "packages": {"critical": [], "security": [], "regular": []},
                "docker": {
                    "has_docker": False,
                    "error": None,
                    "containers": 0,
                    "images_total": 0,
                    "images_outdated": 0,
                    "outdated_images": []
                },
                "disk": {
                    "alert": False,
                    "threshold": self.disk_threshold,
                    "partitions": [],
                    "error": "Vérification disque non effectuée (erreur générale)."
                }
            }
        finally:
            ssh.close()

    def _detect_distribution(self, ssh) -> str:
        """
        Détecte la distribution Linux
        """
        stdin, stdout, stderr = ssh.exec_command(
            "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || echo 'unknown'"
        )
        os_info = stdout.read().decode().lower()

        if "ubuntu" in os_info:
            return "ubuntu"
        elif "debian" in os_info:
            return "debian"
        elif "centos" in os_info:
            return "centos"
        elif "red hat" in os_info or "rhel" in os_info:
            return "rhel"
        elif "fedora" in os_info:
            return "fedora"
        elif "suse" in os_info or "opensuse" in os_info:
            return "opensuse"
        else:
            return "unknown"

    def _check_apt(self, ssh, name: str, ip: str, distro: str) -> Dict[str, Any]:
        """
        Vérifie les mises à jour APT (Debian/Ubuntu)
        """
        try:
            ssh.exec_command("sudo apt-get update 2>&1")
            time.sleep(1)

            stdin, stdout, stderr = ssh.exec_command("apt list --upgradable 2>/dev/null")
            all_updates = stdout.read().decode().strip().split('\n')
            all_packages = [line for line in all_updates if '/' in line]

            stdin, stdout, stderr = ssh.exec_command("apt list --upgradable 2>/dev/null | grep -i security")
            security_updates = stdout.read().decode().strip().split('\n')
            security_packages = [line for line in security_updates if '/' in line]

            critical_packages = []
            critical_keywords = self.config["securite"]["paquets_critiques"]

            for package in security_packages:
                pkg_name = package.split('/')[0].lower()
                if any(keyword in pkg_name for keyword in critical_keywords):
                    critical_packages.append(package.split('/')[0])

            security_pkg_names = [pkg.split('/')[0] for pkg in security_packages]
            regular_packages = []
            for package in all_packages:
                pkg_name = package.split('/')[0]
                if pkg_name not in security_pkg_names:
                    regular_packages.append(pkg_name)

            if critical_packages:
                status = "critical"
            elif security_packages:
                status = "security"
            elif all_packages:
                status = "regular"
            else:
                status = "up-to-date"

            return {
                "name": name,
                "ip": ip,
                "status": status,
                "error": None,
                "distribution": distro,
                "updates": {
                    "total": len(all_packages),
                    "critical": len(critical_packages),
                    "security": len(security_packages) - len(critical_packages),
                    "regular": len(regular_packages)
                },
                "packages": {
                    "critical": critical_packages,
                    "security": [pkg.split('/')[0] for pkg in security_packages if pkg.split('/')[0] not in critical_packages],
                    "regular": regular_packages
                }
            }

        except Exception as e:
            return {
                "name": name,
                "ip": ip,
                "status": "error",
                "error": f"Erreur APT: {str(e)}",
                "distribution": distro,
                "updates": {"total": 0, "critical": 0, "security": 0, "regular": 0},
                "packages": {"critical": [], "security": [], "regular": []}
            }

    def _check_dnf(self, ssh, name: str, ip: str, distro: str) -> Dict[str, Any]:
        """
        Vérifie les mises à jour DNF (Fedora)
        """
        try:
            stdin, stdout, stderr = ssh.exec_command("dnf check-update 2>/dev/null | grep -E '^[a-zA-Z0-9]'")
            all_updates = stdout.read().decode().strip().split('\n')
            all_packages = [line.split()[0] for line in all_updates if line]

            stdin, stdout, stderr = ssh.exec_command("dnf check-update --security 2>/dev/null | grep -E '^[a-zA-Z0-9]'")
            security_updates = stdout.read().decode().strip().split('\n')
            security_packages = [line.split()[0] for line in security_updates if line]

            critical_packages = []
            critical_keywords = self.config["securite"]["paquets_critiques"]

            for package in security_packages:
                pkg_name = package.lower()
                if any(keyword in pkg_name for keyword in critical_keywords):
                    critical_packages.append(package)

            regular_packages = [pkg for pkg in all_packages if pkg not in security_packages]

            if critical_packages:
                status = "critical"
            elif security_packages:
                status = "security"
            elif all_packages:
                status = "regular"
            else:
                status = "up-to-date"

            return {
                "name": name,
                "ip": ip,
                "status": status,
                "error": None,
                "distribution": distro,
                "updates": {
                    "total": len(all_packages),
                    "critical": len(critical_packages),
                    "security": len(security_packages) - len(critical_packages),
                    "regular": len(regular_packages)
                },
                "packages": {
                    "critical": critical_packages,
                    "security": [pkg for pkg in security_packages if pkg not in critical_packages],
                    "regular": regular_packages
                }
            }

        except Exception as e:
            return {
                "name": name,
                "ip": ip,
                "status": "error",
                "error": f"Erreur DNF: {str(e)}",
                "distribution": distro,
                "updates": {"total": 0, "critical": 0, "security": 0, "regular": 0},
                "packages": {"critical": [], "security": [], "regular": []}
            }

    def _check_yum(self, ssh, name: str, ip: str, distro: str) -> Dict[str, Any]:
        """
        Vérifie les mises à jour YUM (CentOS/RHEL)
        """
        try:
            stdin, stdout, stderr = ssh.exec_command("yum check-update 2>/dev/null | grep -E '^[a-zA-Z0-9]'")
            all_updates = stdout.read().decode().strip().split('\n')
            all_packages = [line.split()[0] for line in all_updates if line]

            stdin, stdout, stderr = ssh.exec_command("yum check-update --security 2>/dev/null | grep -E '^[a-zA-Z0-9]'")
            security_updates = stdout.read().decode().strip().split('\n')
            security_packages = [line.split()[0] for line in security_updates if line]

            critical_packages = []
            critical_keywords = self.config["securite"]["paquets_critiques"]

            for package in security_packages:
                pkg_name = package.lower()
                if any(keyword in pkg_name for keyword in critical_keywords):
                    critical_packages.append(package)

            regular_packages = [pkg for pkg in all_packages if pkg not in security_packages]

            if critical_packages:
                status = "critical"
            elif security_packages:
                status = "security"
            elif all_packages:
                status = "regular"
            else:
                status = "up-to-date"

            return {
                "name": name,
                "ip": ip,
                "status": status,
                "error": None,
                "distribution": distro,
                "updates": {
                    "total": len(all_packages),
                    "critical": len(critical_packages),
                    "security": len(security_packages) - len(critical_packages),
                    "regular": len(regular_packages)
                },
                "packages": {
                    "critical": critical_packages,
                    "security": [pkg for pkg in security_packages if pkg not in critical_packages],
                    "regular": regular_packages
                }
            }

        except Exception as e:
            return {
                "name": name,
                "ip": ip,
                "status": "error",
                "error": f"Erreur YUM: {str(e)}",
                "distribution": distro,
                "updates": {"total": 0, "critical": 0, "security": 0, "regular": 0},
                "packages": {"critical": [], "security": [], "regular": []}
            }

    def _generate_report(self) -> str:
        """
        Génère un rapport détaillé et le sauvegarde
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(self.report_dir, f"rapport_smajs_{timestamp}.txt")

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SMAJS - RAPPORT DE SÉCURITÉ\n")
            f.write(f"Date: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            total_machines = len(self.machines)
            successful_checks = sum(1 for r in self.results.values() if r["status"] != "error")
            critical_machines = sum(1 for r in self.results.values() if r["status"] == "critical")
            security_machines = sum(1 for r in self.results.values() if r["status"] == "security")

            docker_machines = sum(
                1 for r in self.results.values()
                if r.get("docker", {}).get("has_docker")
            )
            docker_machines_outdated = sum(
                1 for r in self.results.values()
                if r.get("docker", {}).get("has_docker") and r["docker"].get("images_outdated", 0) > 0
            )
            disk_alert_machines = sum(
                1 for r in self.results.values()
                if r.get("disk", {}).get("alert")
            )

            f.write("📊 STATISTIQUES GLOBALES\n")
            f.write("-" * 40 + "\n")
            f.write(f"Machines vérifiées: {total_machines}\n")
            f.write(f"Vérifications réussies: {successful_checks}\n")
            f.write(f"Machines critiques: {critical_machines}\n")
            f.write(f"Machines avec mises à jour de sécurité: {security_machines}\n")
            f.write(f"Machines avec Docker: {docker_machines}\n")
            f.write(f"Machines avec images Docker potentiellement à mettre à jour: {docker_machines_outdated}\n")
            f.write(f"Machines avec alerte disque (>={self.disk_threshold}% utilisé): {disk_alert_machines}\n\n")

            for name, result in self.results.items():
                f.write(f"🔧 {name} ({result['ip']})\n")
                f.write(f"   Distribution: {result['distribution']}\n")
                f.write(f"   Statut: {self._get_status_text(result['status'])}\n")

                if result["error"]:
                    f.write(f"   Erreur: {result['error']}\n")
                else:
                    updates = result["updates"]
                    f.write(f"   Total mises à jour: {updates['total']}\n")
                    f.write(f"   Mises à jour critiques: {updates['critical']}\n")
                    f.write(f"   Mises à jour de sécurité: {updates['security']}\n")
                    f.write(f"   Mises à jour régulières: {updates['regular']}\n")

                    if updates['critical'] > 0:
                        f.write("   Paquets critiques:\n")
                        for pkg in result["packages"]["critical"][:5]:
                            f.write(f"     • {pkg}\n")
                        if updates['critical'] > 5:
                            f.write(f"     ... et {updates['critical'] - 5} autres\n")

                docker_info = result.get("docker", {})
                if docker_info.get("has_docker"):
                    f.write("   🐳 Docker:\n")
                    f.write(f"     • Conteneurs en cours: {docker_info.get('containers', 0)}\n")
                    f.write(f"     • Images utilisées: {docker_info.get('images_total', 0)}\n")
                    if docker_info.get("images_outdated", 0) > 0:
                        f.write(f"     • Images potentiellement à mettre à jour: {docker_info['images_outdated']}\n")
                        for img in docker_info.get("outdated_images", [])[:5]:
                            f.write(f"       - {img}\n")
                        if docker_info["images_outdated"] > 5:
                            f.write(f"       ... et {docker_info['images_outdated'] - 5} autres\n")
                    else:
                        f.write("     • Aucune image Docker nécessitant une attention particulière détectée (info indicative).\n")
                elif docker_info.get("error"):
                    f.write(f"   🐳 Docker: erreur lors de la vérification ({docker_info['error']})\n")

                disk_info = result.get("disk", {})
                if disk_info.get("alert"):
                    f.write("   💽 Alerte disque (>= {0}% utilisé):\n".format(disk_info.get("threshold", self.disk_threshold)))
                    for part in disk_info.get("partitions", []):
                        f.write(
                            "     • {fs} monté sur {mp} : {used}% utilisé\n".format(
                                fs=part["filesystem"],
                                mp=part["mountpoint"],
                                used=part["used_percent"],
                            )
                        )
                elif disk_info.get("error"):
                    f.write(f"   💽 Disque: erreur lors de la vérification ({disk_info['error']})\n")

                f.write("\n")

            f.write("💡 RECOMMANDATIONS\n")
            f.write("-" * 40 + "\n")

            if critical_machines > 0:
                f.write("🚨 ACTION IMMÉDIATE REQUISE:\n")
                f.write("   • Mettre à jour les paquets critiques IMMÉDIATEMENT\n")
                f.write("   • Vérifier les logs système après mise à jour\n")
                f.write("   • Redémarrer si nécessaire\n")
            elif security_machines > 0:
                f.write("⚠️  ACTION RECOMMANDÉE:\n")
                f.write("   • Planifier les mises à jour de sécurité\n")
                f.write("   • Appliquer les correctifs lors de la prochaine maintenance\n")
            else:
                f.write("✅ SYSTÈME STABLE:\n")
                f.write("   • Continuer la surveillance régulière\n")
                f.write("   • Maintenir les bonnes pratiques de sécurité\n")

        print(f"📄 Rapport généré: {report_file}")
        return report_file

    def _get_status_text(self, status: str) -> str:
        status_map = {
            "critical": "🚨 CRITIQUE",
            "security": "⚠️  SÉCURITÉ",
            "regular": "📄 RÉGULIER",
            "up-to-date": "✅ À JOUR",
            "error": "❌ ERREUR",
            "warning": "⚠️  AVERTISSEMENT"
        }
        return status_map.get(status, status)

    def _generate_email_content(self) -> Tuple[str, str]:
        total_machines = len(self.machines)
        critical_machines = sum(1 for r in self.results.values() if r["status"] == "critical")
        security_machines = sum(1 for r in self.results.values() if r["status"] == "security")
        regular_machines = sum(1 for r in self.results.values() if r["status"] == "regular")
        up_to_date_machines = sum(1 for r in self.results.values() if r["status"] == "up-to-date")

        docker_machines = sum(
            1 for r in self.results.values()
            if r.get("docker", {}).get("has_docker")
        )
        docker_machines_outdated = sum(
            1 for r in self.results.values()
            if r.get("docker", {}).get("has_docker") and r["docker"].get("images_outdated", 0) > 0
        )
        disk_alert_machines = sum(
            1 for r in self.results.values()
            if r.get("disk", {}).get("alert")
        )

        text_content = f"SMAJS - Rapport de sécurité\nDate: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n"
        text_content += f"Machines vérifiées: {total_machines}\n"
        text_content += (
            f"Critiques: {critical_machines} | Sécurité: {security_machines} | "
            f"Régulières: {regular_machines} | À jour: {up_to_date_machines}\n"
        )
        text_content += (
            f"Docker: {docker_machines} machine(s) avec Docker, "
            f"{docker_machines_outdated} avec images potentiellement à mettre à jour\n"
        )
        text_content += (
            f"Disque: {disk_alert_machines} machine(s) avec au moins une partition à >={self.disk_threshold}% d'utilisation\n\n"
        )

        for name, result in self.results.items():
            text_content += f"{name} ({result['ip']}) - {result['distribution']}\n"
            text_content += f"Statut: {self._get_status_text(result['status'])}\n"
            if result["error"]:
                text_content += f"Erreur: {result['error']}\n"
            else:
                updates = result["updates"]
                text_content += (
                    f"Mises à jour: {updates['total']} "
                    f"(Critiques: {updates['critical']}, "
                    f"Sécurité: {updates['security']}, "
                    f"Régulières: {updates['regular']})\n"
                )

            docker_info = result.get("docker", {})
            if docker_info.get("error"):
                text_content += f"Docker: erreur lors de la vérification ({docker_info['error']})\n"
            elif docker_info.get("has_docker"):
                if docker_info.get("containers", 0) > 0 or docker_info.get("images_total", 0) > 0:
                    text_content += (
                        f"Docker: {docker_info.get('containers', 0)} conteneur(s), "
                        f"{docker_info.get('images_outdated', 0)} image(s) potentiellement à mettre à jour\n"
                    )

            disk_info = result.get("disk", {})
            if disk_info.get("error"):
                text_content += f"Disque: erreur lors de la vérification ({disk_info['error']})\n"
            elif disk_info.get("alert"):
                text_content += "Disque: ALERTES (>= {0}% utilisé):\n".format(disk_info.get("threshold", self.disk_threshold))
                for part in disk_info.get("partitions", []):
                    text_content += (
                        f"  - {part['filesystem']} monté sur {part['mountpoint']}: "
                        f"{part['used_percent']}% utilisé\n"
                    )

            text_content += "\n"

        def status_color(status: str) -> str:
            if status == "critical":
                return "#FF4D4F"
            if status == "security":
                return "#FAAD14"
            if status == "regular":
                return "#1890FF"
            if status == "up-to-date":
                return "#52C41A"
            return "#8c8c8c"

        now_str = datetime.now().strftime('%d/%m/%Y à %H:%M:%S')

        html = f"""
<html>
<body style="margin:0; padding:0; background-color:#0b0c10; font-family:'Segoe UI', Tahoma, sans-serif;">
<div style="max-width:900px; margin:20px auto; background-color:#111320; border-radius:12px; overflow:hidden; box-shadow:0 4px 20px rgba(0,0,0,0.6); border:1px solid #1f2333;">

    <div style="background:linear-gradient(135deg,#1c1f37 0%,#0b0c18 100%); padding:40px 30px; text-align:left; border-bottom:1px solid #262b40;">
    <div style="display:flex; align-items:center;">
        <div style="font-size:40px; margin-right:15px;">🔐</div>
        <div>
        <h1 style="color:#ffffff; margin:0; font-size:30px; letter-spacing:1px;">SMAJS</h1>
        <p style="color:#4F62FF; margin:4px 0 0 0; font-size:13px; font-weight:bold; text-transform:uppercase;">
            Suivi des mises à jour de sécurité
        </p>
        </div>
    </div>
    <p style="color:#9ca3c7; margin:18px 0 0 0; font-size:13px;">
        Rapport généré le {now_str}
    </p>
    </div>

    <div style="padding:25px 30px; background-color:#151729; border-bottom:1px solid #1f2333;">
    <table cellpadding="0" cellspacing="0" style="width:100%; border-collapse:collapse;">
        <tr>
        <td style="padding:10px;">
            <div style="background-color:#1f2236; border-radius:10px; padding:15px; text-align:center; border:1px solid {('#FF4D4F' if critical_machines else '#1f2333')};">
            <div style="color:#FF4D4F; font-size:26px; font-weight:bold;">{critical_machines}</div>
            <div style="color:#d9d9d9; font-size:13px; text-transform:uppercase; letter-spacing:1px; margin-top:4px;">🚨 Critiques</div>
            </div>
        </td>
        <td style="padding:10px;">
            <div style="background-color:#1f2236; border-radius:10px; padding:15px; text-align:center; border:1px solid {('#FAAD14' if security_machines else '#1f2333')};">
            <div style="color:#FAAD14; font-size:26px; font-weight:bold;">{security_machines}</div>
            <div style="color:#d9d9d9; font-size:13px; text-transform:uppercase; letter-spacing:1px; margin-top:4px;">⚠️ Sécurité</div>
            </div>
        </td>
        <td style="padding:10px;">
            <div style="background-color:#1f2236; border-radius:10px; padding:15px; text-align:center; border:1px solid #1f2333;">
            <div style="color:#1890FF; font-size:26px; font-weight:bold;">{regular_machines}</div>
            <div style="color:#d9d9d9; font-size:13px; text-transform:uppercase; letter-spacing:1px; margin-top:4px;">📄 Régulières</div>
            </div>
        </td>
        <td style="padding:10px;">
            <div style="background-color:#1f2236; border-radius:10px; padding:15px; text-align:center; border:1px solid #1f2333;">
            <div style="color:#52C41A; font-size:26px; font-weight:bold;">{up_to_date_machines}</div>
            <div style="color:#d9d9d9; font-size:13px; text-transform:uppercase; letter-spacing:1px; margin-top:4px;">✅ À jour</div>
            </div>
        </td>
        </tr>
    </table>
    </div>

    <div style="padding:10px 30px 0 30px; background-color:#151729; border-bottom:1px solid #1f2333;">
        <table cellpadding="0" cellspacing="0" style="width:100%; border-collapse:collapse;">
            <tr>
                <td style="padding:8px 0; color:#9ca3c7; font-size:12px;">
                    🐳 Docker :
                    <span style="color:#ffffff; font-weight:600;">{docker_machines}</span> machine(s) avec Docker,
                    <span style="color:{('#FAAD14' if docker_machines_outdated else '#9ca3c7')}; font-weight:600;">
                        {docker_machines_outdated}</span> avec images potentiellement à mettre à jour
                    <br/>
                    💽 Disque :
                    <span style="color:{('#FF4D4F' if disk_alert_machines else '#9ca3c7')}; font-weight:600;">
                        {disk_alert_machines}</span> machine(s) avec au moins une partition à ≥{self.disk_threshold}% d'utilisation
                </td>
            </tr>
        </table>
    </div>

    <div style="padding:30px;">
    <h2 style="color:#ffffff; font-size:22px; margin:0 0 20px 0; border-left:5px solid #4F62FF; padding-left:12px;">
        📋 ÉTAT DES SYSTÈMES
    </h2>
"""

        if critical_machines > 0:
            html += f"""
    <div style="margin-bottom:25px; padding:18px 20px; border-radius:10px; background-color:#2d0002; border:1px solid #FF4D4F;">
        <div style="color:#FF4D4F; font-weight:bold; font-size:15px; margin-bottom:6px;">🚨 ALERTE CRITIQUE</div>
        <div style="color:#ffd6d6; font-size:13px;">
        {critical_machines} machine(s) présente(nt) des mises à jour <strong>critiques</strong>. Une intervention immédiate est recommandée.
        </div>
    </div>
"""

        for name, result in self.results.items():
            col_badge = status_color(result["status"])
            updates = result["updates"]
            status_text = self._get_status_text(result["status"])
            docker_info = result.get("docker", {})

            html += f"""
    <div style="margin-bottom:22px; padding:20px; border-radius:12px; background-color:#151729; border:1px solid {col_badge};">
        <table cellpadding="0" cellspacing="0" style="width:100%; border-collapse:collapse;">
        <tr>
            <td style="vertical-align:top;">
            <div style="color:#ffffff; font-size:18px; font-weight:bold; margin-bottom:4px;">{name}</div>
            <div style="color:#9ca3c7; font-size:13px; margin-bottom:8px; font-family:Consolas,monospace;">
                {result['ip']} • {result['distribution']}
            </div>
            </td>
            <td style="vertical-align:top; text-align:right;">
            <span style="display:inline-block; padding:6px 12px; border-radius:999px; background-color:{col_badge}; color:#000; font-size:11px; font-weight:bold; text-transform:uppercase; letter-spacing:1px;">
                {status_text}
            </span>
            </td>
        </tr>
        </table>

        <table cellpadding="0" cellspacing="0" style="width:100%; border-collapse:collapse; margin-top:14px;">
        <tr>
            <td style="padding:6px 10px; color:#9ca3c7; font-size:12px;">Total MAJ</td>
            <td style="padding:6px 10px; color:#ffffff; font-size:14px; font-weight:600;">{updates['total']}</td>
            <td style="padding:6px 10px; color:#9ca3c7; font-size:12px;">Critiques</td>
            <td style="padding:6px 10px; color:#FF4D4F; font-size:14px; font-weight:600;">{updates['critical']}</td>
        </tr>
        <tr>
            <td style="padding:6px 10px; color:#9ca3c7; font-size:12px;">Sécurité</td>
            <td style="padding:6px 10px; color:#FAAD14; font-size:14px; font-weight:600;">{updates['security']}</td>
            <td style="padding:6px 10px; color:#9ca3c7; font-size:12px;">Régulières</td>
            <td style="padding:6px 10px; color:#1890FF; font-size:14px; font-weight:600;">{updates['regular']}</td>
        </tr>
        </table>
"""

            if result["error"]:
                html += f"""
        <div style="margin-top:14px; padding:10px 12px; border-radius:8px; background-color:#2b1a1a; border:1px solid #aa3a3a; color:#ffd6d6; font-size:12px;">
        ⚠️ Erreur lors de la vérification : {result['error']}
        </div>
"""
            else:
                crit_pkgs = result["packages"]["critical"][:6]
                sec_pkgs = result["packages"]["security"][:6]

                if crit_pkgs or sec_pkgs:
                    html += '<div style="margin-top:14px;">'

                    if crit_pkgs:
                        html += """
        <div style="margin-bottom:6px; color:#FF4D4F; font-size:12px; font-weight:bold;">Paquets critiques :</div>
        <div style="margin-bottom:8px;">
"""
                        for p in crit_pkgs:
                            html += f"""
            <span style="display:inline-block; margin:2px 4px 2px 0; padding:4px 8px; border-radius:999px; background-color:#3a1113; color:#ffd6d6; font-size:11px; font-family:Consolas,monospace;">
            {p}
            </span>
"""
                        if len(result["packages"]["critical"]) > len(crit_pkgs):
                            html += '<span style="color:#ffd6d6; font-size:11px;">…</span>'
                        html += "</div>"

                    if sec_pkgs:
                        html += """
        <div style="margin-top:6px; margin-bottom:4px; color:#FAAD14; font-size:12px; font-weight:bold;">Paquets de sécurité :</div>
        <div>
"""
                        for p in sec_pkgs:
                            html += f"""
            <span style="display:inline-block; margin:2px 4px 2px 0; padding:4px 8px; border-radius:999px; background-color:#3a2708; color:#ffe7b8; font-size:11px; font-family:Consolas,monospace;">
            {p}
            </span>
"""
                        if len(result["packages"]["security"]) > len(sec_pkgs):
                            html += '<span style="color:#ffe7b8; font-size:11px;">…</span>'
                        html += "</div>"

                    html += "</div>"

            if docker_info.get("error"):
                html += """
        <div style="margin-top:14px; padding:10px 12px; border-radius:8px; background-color:#111320; border:1px dashed #1f2333; font-size:12px; color:#9ca3c7;">
            <div style="margin-bottom:6px; font-weight:600; color:#4F62FF;">🐳 Docker</div>
"""
                html += f"""
            <div style="color:#FF4D4F;">Erreur lors de la vérification Docker : {docker_info['error']}</div>
        </div>
"""
            elif docker_info.get("has_docker") and (
                docker_info.get("containers", 0) > 0 or docker_info.get("images_total", 0) > 0
            ):
                html += """
        <div style="margin-top:14px; padding:10px 12px; border-radius:8px; background-color:#111320; border:1px dashed #1f2333; font-size:12px; color:#9ca3c7;">
            <div style="margin-bottom:6px; font-weight:600; color:#4F62FF;">🐳 Docker</div>
"""
                html += f"""
            <div>Conteneurs actifs : <span style="color:#ffffff; font-weight:600;">{docker_info.get('containers', 0)}</span></div>
            <div>Images utilisées : <span style="color:#ffffff; font-weight:600;">{docker_info.get('images_total', 0)}</span></div>
"""
                if docker_info.get("images_outdated", 0) > 0:
                    html += f"""
            <div style="margin-top:6px;">
                Images potentiellement à mettre à jour :
                <span style="color:#FAAD14; font-weight:600;">{docker_info['images_outdated']}</span>
            </div>
            <div style="margin-top:4px;">
"""
                    for img in docker_info.get("outdated_images", [])[:4]:
                        html += f"""
                <span style="display:inline-block; margin:2px 4px 2px 0; padding:3px 8px; border-radius:999px; background-color:#1f2236; color:#e5e7eb; font-size:11px; font-family:Consolas,monospace;">
                    {img}
                </span>
"""
                    if docker_info["images_outdated"] > 4:
                        html += """
                <span style="color:#9ca3c7; font-size:11px;">…</span>
"""
                    html += """
            </div>
"""

                html += """
        </div>
"""

            disk_info = result.get("disk", {})
            if disk_info.get("error"):
                html += """
        <div style="margin-top:14px; padding:10px 12px; border-radius:8px; background-color:#2b1a1a; border:1px solid #aa3a3a; font-size:12px; color:#ffd6d6;">
            💽 Erreur lors de la vérification disque : {err}
        </div>
""".format(err=disk_info["error"])
            elif disk_info.get("alert"):
                html += """
        <div style="margin-top:14px; padding:10px 12px; border-radius:8px; background-color:#111320; border:1px solid #FF4D4F; font-size:12px; color:#e5e7eb;">
            <div style="margin-bottom:6px; font-weight:600; color:#FF4D4F;">💽 Alerte disque (>= {threshold}% utilisé)</div>
""".format(threshold=disk_info.get("threshold", self.disk_threshold))
                for part in disk_info.get("partitions", []):
                    html += """
            <div>
                <span style="font-family:Consolas,monospace; color:#9ca3c7;">{fs}</span>
                monté sur <span style="font-family:Consolas,monospace; color:#e5e7eb;">{mp}</span> :
                <span style="color:#FF4D4F; font-weight:600;">{used}%</span> utilisé
            </div>
""".format(
    fs=part["filesystem"],
    mp=part["mountpoint"],
    used=part["used_percent"]
)
                html += """
        </div>
"""

            html += """
    </div>
"""

        html += """
    <div style="margin-top:30px; padding:18px 20px; border-radius:10px; background-color:#151729; border:1px solid #1f2333;">
        <div style="color:#4F62FF; font-size:14px; font-weight:bold; margin-bottom:6px;">💡 Recommandations</div>
        <div style="color:#d9d9d9; font-size:13px; line-height:1.6;">
"""
        if critical_machines > 0:
            html += """
        <strong>Action immédiate requise :</strong><br>
        • Mettre à jour les paquets critiques URGEMMENT.<br>
        • Redémarrer les services ou les machines après les mises à jour.
"""
        elif security_machines > 0:
            html += """
        <strong>Action recommandée :</strong><br>
        • Planifier les mises à jour de sécurité sous 7 jours maximum.<br>
        • Appliquer les correctifs lors de la prochaine fenêtre de maintenance.
"""
        else:
            html += """
        <strong>Système stable :</strong><br>
        • Continuer la surveillance régulière des mises à jour.<br>
        • Vérifier périodiquement les images Docker si utilisées en production.
"""

        html += """
        </div>
    </div>
    </div>

    <div style="background-color:#0b0c16; padding:20px; text-align:center; color:#6b7280; font-size:11px; border-top:1px solid #1f2333;">
    Ce rapport est généré automatiquement par <strong style="color:#4F62FF;">SMAJS</strong>.<br>
    Script de suivi des mises à jour de sécurité créé par TBDwarf.
    </div>

</div>
</body>
</html>
"""

        return text_content, html

    def _send_email(self, report_file: str):
        smtp_config = self.config["smtp"]

        try:
            text_content, html_content = self._generate_email_content()

            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"{smtp_config['subject_prefix']} - {datetime.now().strftime('%d/%m/%Y')}"
            msg['From'] = smtp_config['sender']
            msg['To'] = smtp_config['recipient']
            msg['Date'] = formatdate(localtime=True)

            msg.attach(MIMEText(text_content, 'plain', 'utf-8'))
            msg.attach(MIMEText(html_content, 'html', 'utf-8'))

            with smtplib.SMTP_SSL(smtp_config['server'], smtp_config['port']) as server:
                server.login(smtp_config['username'], smtp_config['password'])
                server.send_message(msg)

            print("📧 Rapport envoyé par email avec succès !")

        except Exception as e:
            print(f"⚠️  Impossible d'envoyer l'email: {e}")

    def run(self):
        print("🚀 SMAJS - Démarrage de la vérification")
        print("=" * 60)
        print(f"📅 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        print(f"🔧 Machines à vérifier: {len(self.machines)}")
        print("=" * 60)

        for i, machine in enumerate(self.machines, 1):
            print(f"\n[{i}/{len(self.machines)}] Vérification de {machine['name']} ({machine['ip']})...")

            result = self._check_machine(machine)
            self.results[machine['name']] = result

            status_text = self._get_status_text(result["status"])
            print(f"   Statut: {status_text}")

            if not result["error"]:
                updates = result["updates"]
                if updates["total"] > 0:
                    print(f"   Mises à jour disponibles: {updates['total']}")
                    print(f"     • Critiques: {updates['critical']}")
                    print(f"     • Sécurité: {updates['security']}")
                    print(f"     • Régulières: {updates['regular']}")
                else:
                    print(f"   ✅ Système à jour")

                docker_info = result.get("docker", {})
                if docker_info.get("has_docker"):
                    print(f"   🐳 Docker: {docker_info.get('containers', 0)} conteneur(s), "
                          f"{docker_info.get('images_outdated', 0)} image(s) potentiellement à mettre à jour")
                elif docker_info.get("error"):
                    print(f"   🐳 Docker: erreur lors de la vérification ({docker_info['error']})")

                disk_info = result.get("disk", {})
                if disk_info.get("alert"):
                    print("   💽 Alerte disque:")
                    for part in disk_info.get("partitions", []):
                        print(f"     • {part['filesystem']} sur {part['mountpoint']}: {part['used_percent']}% utilisé")
                elif disk_info.get("error"):
                    print(f"   💽 Disque: erreur lors de la vérification ({disk_info['error']})")

            time.sleep(0.5)

        print("\n" + "=" * 60)
        print("📊 Génération du rapport...")
        report_file = self._generate_report()

        print("\n🗑️  Nettoyage des anciens rapports...")
        self._clean_old_reports()

        # Décision d'envoi du mail
        critical_count = sum(1 for r in self.results.values() if r["status"] == "critical")
        disk_alert_machines = sum(
            1 for r in self.results.values()
            if r.get("disk", {}).get("alert")
        )
        today_weekday = datetime.now().weekday()  # 0=lundi ... 6=dimanche
        jour_rapport = self.config.get("planification", {}).get("jour_rapport", 4)

        doit_envoyer = False
        raison = ""

        if critical_count > 0:
            doit_envoyer = True
            raison = "mises à jour CRITIQUES détectées"
        elif disk_alert_machines > 0:
            doit_envoyer = True
            raison = "alerte(s) disque détectée(s) (>= {0}% utilisé)".format(self.disk_threshold)
        elif today_weekday == jour_rapport:
            doit_envoyer = True
            raison = "jour de rapport planifié"

        if doit_envoyer:
            print(f"\n📧 Envoi du rapport par email... ({raison})")
            self._send_email(report_file)
        else:
            print("\n📧 Aucun email envoyé (pas de critiques, pas d'alerte disque et pas jour de rapport planifié).")

        print("\n" + "=" * 60)
        print("✅ VÉRIFICATION TERMINÉE")
        print("=" * 60)

        if critical_count > 0:
            print(f"\n🚨 ALERTE: {critical_count} machine(s) nécessite(nt) une action IMMÉDIATE !")
            for name, result in self.results.items():
                if result["status"] == "critical":
                    print(f"   • {name}: {result['updates']['critical']} paquet(s) critique(s)")

        # Résumé des alertes disque (optionnel mais utile)
        if disk_alert_machines > 0:
            print(f"\n💽 ALERTE DISQUE: {disk_alert_machines} machine(s) avec au moins une partition à >={self.disk_threshold}% d'utilisation !")
            for name, result in self.results.items():
                disk_info = result.get("disk", {})
                if disk_info.get("alert"):
                    print(f"   • {name}:")
                    for part in disk_info.get("partitions", []):
                        print(f"       - {part['filesystem']} sur {part['mountpoint']}: {part['used_percent']}% utilisé")

        print(f"\n📄 Rapport disponible: {report_file}")
        if doit_envoyer:
            print("📧 Rapport envoyé par email")
        else:
            print("📧 Rapport NON envoyé (condition de planification)")
        print("🗑️  Anciens rapports nettoyés")
        print("\n" + "=" * 60)

def main():
    print("""
    ╔══════════════════════════════════════════════╗
    ║               SMAJS v2.2                     ║
    ║  Surveillance des Mises à Jour de Sécurité   ║
    ╚══════════════════════════════════════════════╝
    """)

    try:
        import paramiko
    except ImportError:
        print("❌ Paramiko n'est pas installé !")
        print("   Exécutez: pip install paramiko")
        sys.exit(1)

    try:
        smajs = SMASJPro()
        smajs.run()
    except KeyboardInterrupt:
        print("\n\n❌ Interrompu par l'utilisateur.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
