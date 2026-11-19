
#!/usr/bin/env bash

# VPS SECURITY AUDIT
# Read-only audit for Ubuntu 22.04 / 24.04

export LC_ALL=C
set -u

GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RESET='\033[0m'

PROBLEMS=0
REPORT="/root/audit-report.txt"

exec > >(tee "$REPORT") 2>&1

section() {
    echo
    echo "============================================================"
    echo " $1"
    echo "============================================================"
}

problem() {
    PROBLEMS=$((PROBLEMS+1))
    echo -e "${RED}[ПРОБЛЕМА] $1${RESET}"
}

echo "############################################################"
echo "#                 VPS SECURITY AUDIT                       #"
echo "############################################################"
echo "Дата: $(date -Is)"
echo "Сервер: $(hostname -f 2>/dev/null || hostname)"
echo "IP сервера:"
hostname -I 2>/dev/null
echo "ОС:"
grep PRETTY_NAME /etc/os-release
echo "Ядро: $(uname -r)"
echo "Период анализа журналов: последние 30 дней"

if [ "$(id -u)" -ne 0 ]; then
    echo "Запусти скрипт от root."
    exit 1
fi

section "1. ПОЛЬЗОВАТЕЛИ И ПРАВА"

getent passwd | awk -F: '$3 == 0 || $3 >= 1000 {
    print $1, "UID="$3, "HOME="$6, "SHELL="$7
}'

echo
echo "Группа sudo:"
getent group sudo

echo
echo "Другие пользователи с UID 0:"
ROOT_USERS=$(getent passwd | awk -F: '$3 == 0 {print $1}')
echo "$ROOT_USERS"

ROOT_COUNT=$(echo "$ROOT_USERS" | wc -l)
if [ "$ROOT_COUNT" -gt 1 ]; then
    problem "Обнаружено несколько пользователей с UID 0."
fi

section "2. SSH НАСТРОЙКИ"

sshd -T 2>/dev/null | grep -E \
'^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeysfile)' || true

echo
grep -RniE \
'^[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|DenyUsers)' \
/etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null || true

section "3. SSH КЛЮЧИ"

for DIR in /root /home; do
    [ -d "$DIR" ] || continue
    find "$DIR" -type f \( -name authorized_keys -o -name authorized_keys2 \) \
        -print 2>/dev/null | while read -r FILE; do
            echo "Файл: $FILE"
            ssh-keygen -lf "$FILE" 2>/dev/null || echo "Ключи не обнаружены"
        done
done

section "4. УСПЕШНЫЕ SSH ВХОДЫ"

LOGIN_FILE=$(mktemp)

{
    grep -hE 'sshd.*Accepted (password|publickey|keyboard-interactive)' \
        /var/log/auth.log /var/log/auth.log.* 2>/dev/null || true

    journalctl --since "30 days ago" -u ssh -u sshd \
        --no-pager 2>/dev/null |
        grep -E 'Accepted (password|publickey|keyboard-interactive)' || true
} | sort -u > "$LOGIN_FILE"

if [ -s "$LOGIN_FILE" ]; then
    cat "$LOGIN_FILE"

    echo
    echo "ПРОВЕРКА IP-АДРЕСОВ"

    mapfile -t IPS < <(
        awk '{
            for (i=1; i<=NF; i++)
                if ($i=="from" && i<NF) print $(i+1)
        }' "$LOGIN_FILE" | sort -u
    )

    for IP in "${IPS[@]}"; do
        echo
        echo -e "${YELLOW}Успешный вход с IP: $IP${RESET}"
        printf "%s" "Это был ты? (y/n): "
        IFS= read -r ANSWER

        case "$ANSWER" in
            y|Y|yes|YES|д|Д|да|ДА)
                echo "IP подтверждён пользователем."
                ;;
            *)
                problem "НЕ ПОДТВЕРЖДЁН УСПЕШНЫЙ ВХОД: $IP"
                ;;
        esac
    done
else
    echo "Записи об успешных входах не найдены в доступных журналах."
fi

rm -f "$LOGIN_FILE"

section "5. НЕУДАЧНЫЕ SSH ВХОДЫ"

if [ -f /var/log/auth.log ]; then
    grep -hEi 'Failed password|Invalid user|authentication failure' \
        /var/log/auth.log /var/log/auth.log.* 2>/dev/null |
        tail -n 100 || true
else
    journalctl --since "30 days ago" --no-pager 2>/dev/null |
        grep -Ei 'Failed password|Invalid user|authentication failure' |
        tail -n 100 || true
fi

section "6. FAIL2BAN"

if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client status 2>&1 || true
    fail2ban-client status sshd 2>&1 || true
else
    echo "Fail2ban не установлен."
fi

section "7. СЕТЕВЫЕ ПОРТЫ"

ss -tulpn 2>&1 || true

echo
echo "Активные соединения:"
ss -tpn state established 2>&1 || true

section "8. ПРОЦЕССЫ"

ps auxww --sort=-%cpu | head -n 60

section "9. СЛУЖБЫ SYSTEMD"

systemctl --failed --no-pager 2>&1 || true

echo
systemctl list-unit-files --type=service --state=enabled --no-pager 2>&1 || true

section "10. SYSTEMD TIMERS"

systemctl list-timers --all --no-pager 2>&1 || true

section "11. CRON"

echo "Системные cron-файлы:"
find /etc/cron.d /etc/cron.daily /etc/cron.hourly \
    /etc/cron.weekly /etc/cron.monthly \
    -maxdepth 2 -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' \
    2>/dev/null || true

echo
echo "Cron root:"
crontab -l -u root 2>&1 || true

echo
echo "Системный crontab:"
cat /etc/crontab 2>/dev/null || true

section "12. ИЗМЕНЁННЫЕ СИСТЕМНЫЕ ФАЙЛЫ"

for DIR in /etc/systemd/system /etc/cron.d /etc/ssh \
    /usr/local/bin /usr/local/sbin /root/.ssh; do
    [ -d "$DIR" ] || continue
    echo
    echo "--- $DIR ---"
    find "$DIR" -type f -mtime -30 \
        -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %p\n' \
        2>/dev/null | sort -r | head -n 50
done

section "13. DOCKER"

if command -v docker >/dev/null 2>&1; then
    docker ps -a --no-trunc 2>&1 || true
    echo
    docker images 2>&1 || true
else
    echo "Docker не установлен."
fi

section "14. ЦЕЛОСТНОСТЬ ПАКЕТОВ"

if command -v dpkg >/dev/null 2>&1; then
    dpkg -V 2>&1 | head -n 150
fi

section "15. МОДУЛИ ЯДРА"

lsmod 2>/dev/null | head -n 80 || true

section "16. СИСТЕМНЫЕ ОШИБКИ"

journalctl -p err --since "7 days ago" \
    --no-pager -n 100 2>&1 || true

section "17. ИСПОЛНЯЕМЫЕ ФАЙЛЫ В TEMP"

for DIR in /tmp /var/tmp /dev/shm; do
    [ -d "$DIR" ] || continue
    echo
    echo "--- $DIR ---"
    find "$DIR" -xdev -type f -perm /111 \
        -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %p\n' \
        2>/dev/null | head -n 50
done

section "18. ИТОГОВЫЙ РЕЗУЛЬТАТ"

echo "Количество неподтверждённых успешных SSH-входов: $PROBLEMS"

if [ "$PROBLEMS" -eq 0 ]; then
    echo
    echo -e "${GREEN}"
    echo "############################################################"
    echo "#                                                          #"
    echo "#             ПРОБЛЕМ НЕ ОБНАРУЖЕНО                       #"
    echo "#                                                          #"
    echo "############################################################"
    echo -e "${RESET}"
    echo "По автоматической проверке нет неподтверждённых SSH-входов."
else
    echo
    echo -e "${RED}"
    echo "############################################################"
    echo "#                                                          #"
    echo "#             ОБНАРУЖЕНЫ ПРОБЛЕМЫ                          #"
    echo "#                                                          #"
    echo "############################################################"
    echo -e "${RESET}"
    echo "Есть неподтверждённые успешные SSH-входы."
    echo "Проверь их IP, дату и пользователя в разделе 4."
fi

echo
echo "Отчёт сохранён: $REPORT"
echo "Сервер: $(hostname)"
echo "Дата завершения: $(date -Is)"
echo
echo "Проверка предварительная. Отсутствие находок не гарантирует"
echo "отсутствие вредоносного ПО или иных способов компрометации."
echo "Скрипт не изменял настройки сервера."

echo
echo "AUDIT FINISHED"
