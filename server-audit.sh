#!/usr/bin/env bash

# Ubuntu VPS Security Audit 1.2
# Non-invasive security audit for Ubuntu 22.04 / 24.04
# Does not modify system configuration or service settings.

export LC_ALL=C
set -u

# Root check BEFORE creating the report.
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Запусти скрипт от root."
    exit 1
fi

REPORT="/root/audit-report.txt"
WARNINGS=0
LIMITATIONS=0
LOGIN_FILE=""

CURRENT_SECTION="Начало проверки"
WARNINGS_LIST=()
LIMITATIONS_LIST=()

# Report and terminal output.
if ! touch "$REPORT"; then
    echo "ERROR: Не удалось создать отчёт: $REPORT"
    exit 1
fi

exec > >(tee "$REPORT") 2>&1

cleanup() {
    if [ -n "$LOGIN_FILE" ] && [ -f "$LOGIN_FILE" ]; then
        rm -f "$LOGIN_FILE"
    fi
}
trap cleanup EXIT

section() {
    CURRENT_SECTION="$1"

    echo
    echo "============================================================"
    echo " $1"
    echo "============================================================"
}

warning() {
    WARNINGS=$((WARNINGS + 1))
    WARNINGS_LIST+=("$CURRENT_SECTION: $1")

    echo "[ПРЕДУПРЕЖДЕНИЕ] $1"
}

limitation() {
    LIMITATIONS=$((LIMITATIONS + 1))
    LIMITATIONS_LIST+=("$CURRENT_SECTION: $1")

    echo "[ОГРАНИЧЕНИЕ ПРОВЕРКИ] $1"
}

info() {
    echo "[ИНФО] $1"
}

echo "############################################################"
echo "#                 VPS SECURITY AUDIT 1.2                   #"
echo "############################################################"
echo "Дата: $(date -Is)"
echo "Сервер: $(hostname -f 2>/dev/null || hostname)"
echo "IP сервера:"
hostname -I 2>/dev/null || true
echo
echo "ОС:"
grep PRETTY_NAME /etc/os-release 2>/dev/null || true
echo "Ядро: $(uname -r)"
echo "Период анализа SSH-журналов: последние 30 дней"
echo "Отчёт: $REPORT"

section "1. ПОЛЬЗОВАТЕЛИ И ПРАВА"

getent passwd | awk -F: '$3 == 0 || $3 >= 1000 {
    print $1, "UID="$3, "HOME="$6, "SHELL="$7
}'

echo
echo "Группа sudo:"
getent group sudo || true

echo
echo "Пользователи с UID 0:"
mapfile -t ROOT_USERS < <(getent passwd | awk -F: '$3 == 0 {print $1}')

if [ "${#ROOT_USERS[@]}" -gt 0 ]; then
    printf '%s\n' "${ROOT_USERS[@]}"
fi

if [ "${#ROOT_USERS[@]}" -gt 1 ]; then
    warning "Обнаружено несколько пользователей с UID 0. Проверьте каждый аккаунт."
fi

section "2. SSH НАСТРОЙКИ"

if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | grep -E \
    '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeysfile)' || true
else
    limitation "Команда sshd не найдена. Эффективные SSH-настройки не проверены."
fi

echo
echo "Настройки в конфигурационных файлах:"
grep -RniE \
'^[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|DenyUsers)' \
/etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null || true

section "3. SSH КЛЮЧИ"

KEY_FILES=()

for DIR in /root /home; do
    [ -d "$DIR" ] || continue

    while IFS= read -r -d '' FILE; do
        KEY_FILES+=("$FILE")
    done < <(
        find "$DIR" -type f \
            \( -name authorized_keys -o -name authorized_keys2 \) \
            -print0 2>/dev/null
    )
done

if [ "${#KEY_FILES[@]}" -eq 0 ]; then
    info "Файлы authorized_keys не найдены."
else
    for FILE in "${KEY_FILES[@]}"; do
        echo
        echo "Файл: $FILE"
        ssh-keygen -lf "$FILE" 2>/dev/null || \
            echo "Публичные ключи не обнаружены или файл пуст."
    done
fi

section "4. УСПЕШНЫЕ SSH ВХОДЫ"

LOGIN_FILE=$(mktemp) || {
    limitation "Не удалось создать временный файл для анализа SSH."
    LOGIN_FILE=""
}

if [ -n "$LOGIN_FILE" ]; then
    # Prefer journal entries limited to the last 30 days.
    if command -v journalctl >/dev/null 2>&1; then
        journalctl --since "30 days ago" _COMM=sshd \
            --no-pager 2>/dev/null |
            grep -E 'Accepted (password|publickey|keyboard-interactive)' \
            > "$LOGIN_FILE" || true
    fi

    # Fallback to the current auth.log if journald has no matching records.
    if [ -n "$LOGIN_FILE" ] && [ ! -s "$LOGIN_FILE" ]; then
        if [ -f /var/log/auth.log ]; then
            grep -hE 'sshd.*Accepted (password|publickey|keyboard-interactive)' \
                /var/log/auth.log 2>/dev/null |
                sort -u > "$LOGIN_FILE" || true

            if [ -s "$LOGIN_FILE" ]; then
                limitation "Использован текущий auth.log: период может быть короче 30 дней."
            fi
        fi
    fi

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
            echo "Успешный вход с IP: $IP"

            while true; do
                printf '%s' "Это был ты? (y/n): "

                ANSWER=""

                if ! IFS= read -r ANSWER; then
                    warning "Не удалось получить ответ для IP: $IP"
                    break
                fi

                # Remove leading and trailing whitespace.
                ANSWER="${ANSWER#"${ANSWER%%[![:space:]]*}"}"
                ANSWER="${ANSWER%"${ANSWER##*[![:space:]]}"}"

                # Normalize Latin letters.
                ANSWER=$(printf '%s' "$ANSWER" | tr '[:upper:]' '[:lower:]')

                case "$ANSWER" in
                    y|yes|д|Д|да|Да|дА|ДА)
                        info "IP подтверждён пользователем: $IP"
                        break
                        ;;

                    n|no|н|Н|нет|Нет|неТ|нЕт|нЕТ|НеТ|НЕт|НЕТ)
                        warning "Пользователь не подтвердил успешный SSH-вход с IP: $IP"
                        break
                        ;;

                    *)
                        echo "[ИНФО] Непонятный ответ."
                        echo "Введи y/yes/д/да или n/no/н/нет."
                        ;;
                esac
            done
        done
    else
        limitation "Не удалось найти записи об успешных SSH-входах. Проверьте доступность и хранение журналов."
    fi
fi

section "5. НЕУДАЧНЫЕ SSH ВХОДЫ"

FAILED_SSH=""

if command -v journalctl >/dev/null 2>&1; then
    FAILED_SSH=$(
        journalctl --since "30 days ago" _COMM=sshd \
            --no-pager 2>/dev/null |
            grep -Ei 'Failed password|Invalid user|authentication failure' |
            tail -n 100 || true
    )
fi

if [ -n "$FAILED_SSH" ]; then
    printf '%s\n' "$FAILED_SSH"
elif [ -f /var/log/auth.log ]; then
    grep -hEi 'Failed password|Invalid user|authentication failure' \
        /var/log/auth.log 2>/dev/null |
        tail -n 100 || true
else
    info "Записи о неудачных SSH-входах не найдены."
fi

section "6. FAIL2BAN"

if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client status 2>&1 || true
    echo
    fail2ban-client status sshd 2>&1 || true
else
    info "Fail2ban не установлен."
fi

section "7. СЕТЕВЫЕ ПОРТЫ"

if command -v ss >/dev/null 2>&1; then
    ss -tulpn 2>&1 || true

    echo
    echo "Активные соединения:"
    ss -tpn state established 2>&1 || true
else
    limitation "Команда ss не найдена."
fi

section "8. ПРОЦЕССЫ"

ps auxww --sort=-%cpu | head -n 60

section "9. СЛУЖБЫ SYSTEMD"

if command -v systemctl >/dev/null 2>&1; then
    echo "Неисправные службы:"
    FAILED_UNITS=$(systemctl --failed --plain --no-legend 2>/dev/null || true)

    if [ -n "$FAILED_UNITS" ]; then
        printf '%s\n' "$FAILED_UNITS"
        warning "Обнаружены службы systemd в состоянии failed. Проверьте их причины."
    else
        info "Неисправные службы systemd не обнаружены."
    fi

    echo
    echo "Включённые службы:"
    systemctl list-unit-files --type=service --state=enabled --no-pager 2>&1 || true
else
    limitation "Команда systemctl не найдена."
fi

section "10. SYSTEMD TIMERS"

systemctl list-timers --all --no-pager 2>&1 || true

section "11. CRON"

echo "Системные cron-файлы:"
find /etc/cron.d /etc/cron.daily /etc/cron.hourly \
    /etc/cron.weekly /etc/cron.monthly \
    -maxdepth 2 -type f \
    -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null || true

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
    echo "Контейнеры:"
    docker ps -a --no-trunc 2>&1 || true

    echo
    echo "Образы:"
    docker images 2>&1 || true
else
    info "Docker не установлен."
fi

section "14. ЦЕЛОСТНОСТЬ ПАКЕТОВ"

if command -v dpkg >/dev/null 2>&1; then

    DPKG_CHANGES=$(dpkg -V 2>&1 || true)

    if [ -z "$DPKG_CHANGES" ]; then
        info "dpkg -V не обнаружил отличий в проверяемых файлах пакетов."
    else
        echo "Обнаруженные отличия:"
        printf '%s\n' "$DPKG_CHANGES"

        CONFIG_CHANGES=()
        OTHER_CHANGES=()
        MISSING_FILES=()

        while IFS= read -r LINE; do
            [ -n "$LINE" ] || continue

            if [[ "$LINE" == *"missing"* ]]; then
                MISSING_FILES+=("$LINE")

            elif [[ "$LINE" =~ ^.{9}[[:space:]]+c[[:space:]] ]]; then
                CONFIG_CHANGES+=("$LINE")

            else
                OTHER_CHANGES+=("$LINE")
            fi
        done <<< "$DPKG_CHANGES"

        echo
        echo "РЕЗУЛЬТАТ АНАЛИЗА:"

        if [ "${#CONFIG_CHANGES[@]}" -gt 0 ]; then
            echo
            echo "Изменённые конфигурационные файлы:"
            printf '%s\n' "${CONFIG_CHANGES[@]}"
            info "Изменения конфигураций сами по себе не считаются признаком взлома."
        fi

        if [ "${#MISSING_FILES[@]}" -gt 0 ]; then
            echo
            echo "Отсутствующие файлы:"
            printf '%s\n' "${MISSING_FILES[@]}"
            warning "Обнаружены отсутствующие файлы пакетов. Проверьте, не удалены ли они намеренно."
        fi

        if [ "${#OTHER_CHANGES[@]}" -gt 0 ]; then
            echo
            echo "Другие отличия:"
            printf '%s\n' "${OTHER_CHANGES[@]}"
            warning "Обнаружены отличия в файлах пакетов, не классифицированных как конфигурационные. Требуется проверка."
        fi
    fi

else
    limitation "Команда dpkg не найдена."
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

    TEMP_FILES=$(
        find "$DIR" -xdev -type f -perm /111 \
            -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %p\n' \
            2>/dev/null | head -n 50
    )

    if [ -n "$TEMP_FILES" ]; then
        printf '%s\n' "$TEMP_FILES"
        warning "Найдены исполняемые файлы в $DIR. Проверьте их назначение."
    else
        info "Исполняемые файлы не обнаружены."
    fi
done

section "18. ИТОГОВЫЙ РЕЗУЛЬТАТ"

echo "Количество предупреждений: $WARNINGS"
echo "Ограничений проверки: $LIMITATIONS"

if [ "$WARNINGS" -gt 0 ]; then
    echo
    echo "############################################################"
    echo "#             ОБНАРУЖЕНЫ ПРЕДУПРЕЖДЕНИЯ                   #"
    echo "############################################################"

    echo
    echo "СПИСОК ОБНАРУЖЕННЫХ ПРОБЛЕМ:"
    echo

    for i in "${!WARNINGS_LIST[@]}"; do
        echo "[$((i + 1))] ${WARNINGS_LIST[$i]}"
    done

    echo
    echo "Необходимо проверить указанные выше разделы."

elif [ "$LIMITATIONS" -gt 0 ]; then
    echo
    echo "############################################################"
    echo "#             ПРОВЕРКА ВЫПОЛНЕНА НЕ ПОЛНОСТЬЮ             #"
    echo "############################################################"

    echo "Некоторые проверки не удалось выполнить или их данные ограничены."

else
    echo
    echo "############################################################"
    echo "#          ПРЕДУПРЕЖДЕНИЙ НЕ ОБНАРУЖЕНО                   #"
    echo "############################################################"

    echo "Автоматические проверки не выявили отмеченных предупреждений."
fi

if [ "$LIMITATIONS" -gt 0 ]; then
    echo
    echo "СПИСОК ОГРАНИЧЕНИЙ ПРОВЕРКИ:"
    echo

    for i in "${!LIMITATIONS_LIST[@]}"; do
        echo "[$((i + 1))] ${LIMITATIONS_LIST[$i]}"
    done

    echo
    echo "Учитывайте ограничения при оценке результатов аудита."
fi

echo
echo "============================================================"
echo " ИНФОРМАЦИЯ ОБ АУДИТЕ"
echo "============================================================"

echo "Отчёт сохранён: $REPORT"
echo "Сервер: $(hostname)"
echo "Дата завершения: $(date -Is)"

echo
echo "ВАЖНО:"
echo "- Это предварительный аудит, а не гарантия отсутствия взлома."
echo "- Неизвестный IP или изменённый файл не обязательно означает взлом."
echo "- Сетевые порты, процессы, cron и службы требуют ручной оценки."
echo "- Скрипт не меняет конфигурацию и состояние системных служб."
echo "- Скрипт создаёт отчёт и временный файл."

echo
echo "AUDIT FINISHED"
