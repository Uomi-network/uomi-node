#!/bin/sh

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'
BOLD='\033[1m'

# Variabili globali
SERVICE_FILE="/etc/systemd/system/uomi.service"
NODE_PATH="/var/lib/uomi"
BINARY_PATH="/usr/local/bin/uomi"
CHAIN_SPEC_PATH="/usr/local/bin/genesis.json"
MIN_RAM_MB=4096
MIN_DISK_GB=100
DEFAULT_RPC_PORT=9944
MAX_STARTUP_TIME=60
LOG_FILE="/var/log/uomi.log"
TMP_DIR=""

# Define spinner frames
SPINNER_FRAMES="⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏"
SPINNER_DELAY=0.1
SPINNER_PID=""

# Color codes
BLUE="\033[34m"
GREEN="\033[32m"
RED="\033[31m"
RESET="\033[0m"

start_spinner() {
    local msg="$1"
    
    # Return if no message provided
    [ -z "$msg" ] && return

    # Display initial message
    printf "%s " "$msg"
    
    # Start spinner in background
    (
        while : ; do
            for frame in $SPINNER_FRAMES; do
                printf "\r${BLUE}%s${RESET} %s" "$frame" "$msg"
                sleep $SPINNER_DELAY
            done
        done
    ) & 

    SPINNER_PID=$!
}

stop_spinner() {
    local result="$1"
    
    # Kill spinner process if exists
    if [ -n "$SPINNER_PID" ]; then
        kill $SPINNER_PID 2>/dev/null
        wait $SPINNER_PID 2>/dev/null
        SPINNER_PID=""
    fi
    
    # Clear line and show final status
    printf "\r"
    if [ "$result" = "success" ]; then
        printf "${GREEN}✓${RESET}\n"
    else
        printf "${RED}✗${RESET}\n"
    fi
}


# Configurazione systemd base
SERVICE_CONTENT_START="[Unit]
Description=Uomi Node
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=uomi
Group=uomi
Restart=always
RestartSec=10
LimitNOFILE=65535"

SERVICE_CONTENT_END="
# Hardening
ProtectSystem=strict
PrivateTmp=true
PrivateDevices=true
NoNewPrivileges=true
ReadWritePaths=${NODE_PATH}
StandardOutput=append:${LOG_FILE}
StandardError=append:${LOG_FILE}

[Install]
WantedBy=multi-user.target"

# Funzione per il logging
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo  "${timestamp} $1" | tee -a $LOG_FILE
}

# Gestione errori
handle_error() {
    log "${RED}Errore alla riga $1${RESET}"
    exit 1
}

trap 'handle_error $LINENO' ERR

# Verifica requisiti di sistema
check_system_requirements() {
    log "${BLUE}Verifico i requisiti di sistema...${RESET}"
    
    # Verifica RAM
    local total_ram=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_ram -lt $MIN_RAM_MB ]; then
        log "${RED}RAM insufficiente. Richiesti almeno ${MIN_RAM_MB}MB${RESET}"
        exit 1
    fi
    
    # Verifica spazio disco
    local free_disk=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ $free_disk -lt $MIN_DISK_GB ]; then
        log "${RED}Spazio disco insufficiente. Richiesti almeno ${MIN_DISK_GB}GB${RESET}"
        exit 1
    fi

    log "${GREEN}✓ Requisiti di sistema verificati${RESET}"
}

# Creazione ambiente sicuro
create_secure_environment() {
    TMP_DIR=$(mktemp -d)
    chmod 700 $TMP_DIR
    
    if [ ! -d $LOG_FILE ]; then
        sudo touch $LOG_FILE
        sudo chmod 644 $LOG_FILE
    fi
    
    log "${GREEN}✓ Ambiente sicuro creato${RESET}"
}

# Funzione sudo wrapper
sudo_command() {
    if [ $(id -u) -ne 0 ]; then
        sudo "$@"
    else
        "$@"
    fi
}

# Installazione dipendenze
install_dependencies() {
    start_spinner "Installazione dipendenze..."
    
    sudo_command apt-get update -y > /dev/null 2>&1
    sudo_command apt-get install -y \
        curl \
        jq \
        build-essential \
        libssl-dev \
        pkg-config \
        cmake \
        git \
        libclang-dev > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        stop_spinner "success"
    else
        stop_spinner "fail"
        log "${RED}Errore nell'installazione delle dipendenze${RESET}"
        exit 1
    fi
}

# Setup chiavi validatore
setup_validator_keys() {
    local node_name=$1
    log "${BLUE}Generazione chiave per il validatore $node_name...${RESET}"

    # Genera una singola chiave Sr25519 che verrà usata per tutti i pallet
    "${BINARY_PATH}" key generate --scheme Sr25519 --output-type json > "${TMP_DIR}/validator.json"
    
    # Verifica che la chiave sia stata generata correttamente
    if ! jq -e '.publicKey' "${TMP_DIR}/validator.json" > /dev/null; then
        log "${RED}Errore nella generazione della chiave${RESET}"
        exit 1
    fi
    
    # Estrai le informazioni della chiave
    jq -r '.secretPhrase' "${TMP_DIR}/validator.json" > "${TMP_DIR}/validator_phrase"
    jq -r '.secretSeed' "${TMP_DIR}/validator.json" > "${TMP_DIR}/validator_seed"
    jq -r '.publicKey' "${TMP_DIR}/validator.json" > "${TMP_DIR}/validator_public"
    
    # Per GRANDPA, converti la stessa chiave in Ed25519
    "${BINARY_PATH}" key inspect --scheme Ed25519 "$(cat ${TMP_DIR}/validator_phrase)" > "${TMP_DIR}/validator_ed.json"
    jq -r '.publicKey' "${TMP_DIR}/validator_ed.json" > "${TMP_DIR}/validator_ed_public"

    chmod 600 "${TMP_DIR}/validator"*
    log "${GREEN}✓ Chiavi generate con successo${RESET}"
}

# Creazione service file
create_service_file() {
    local node_type=$1
    local node_name=$2
    local service_content=""
    
    case "${node_type}" in
        validator)
            service_content="ExecStart=${BINARY_PATH} \\
    --validator \\
    --name \"${node_name}\" \\
    --chain \"${CHAIN_SPEC_PATH}\" \\
    --base-path \"${NODE_PATH}\" \\
    --state-pruning 1000 \\
    --blocks-pruning 1000 \\
    --enable-evm-rpc \\
    --rpc-cors all \\
    --rpc-methods Safe \\
    --prometheus-external \\
    --no-telemetry"
            ;;
        archive)
            service_content="ExecStart=${BINARY_PATH} \\
    --name \"${node_name}\" \\
    --chain \"${CHAIN_SPEC_PATH}\" \\
    --base-path \"${NODE_PATH}\" \\
    --pruning archive \\
    --rpc-cors all \\
    --rpc-external \\
    --ws-external \\
    --rpc-methods Safe \\
    --enable-evm-rpc \\
    --prometheus-external"
            ;;
        full)
            service_content="ExecStart=${BINARY_PATH} \\
    --name \"${node_name}\" \\
    --chain \"${CHAIN_SPEC_PATH}\" \\
    --base-path \"${NODE_PATH}\" \\
    --pruning 1000 \\
    --rpc-cors all \\
    --rpc-external \\
    --ws-external \\
    --rpc-methods Safe"
            ;;
    esac

    echo -e "${SERVICE_CONTENT_START}\n${service_content}\n${SERVICE_CONTENT_END}" | sudo tee "${SERVICE_FILE}" > /dev/null
    log "${GREEN}✓ Service file creato${RESET}"
}
# Setup nodo
setup_node() {
    start_spinner "Configurazione nodo..."
    
    # Crea utente per il servizio
    sudo_command useradd --no-create-home --shell /usr/sbin/nologin uomi > /dev/null 2>&1 || true
    
    # Crea directory necessarie
    sudo_command mkdir -p $NODE_PATH
    sudo_command chown -R uomi:uomi $NODE_PATH
    
    # Copia i file necessari
    if [ -f ./genesis.json ]; then
        sudo_command cp ./genesis.json $CHAIN_SPEC_PATH
    else
        stop_spinner "fail"
        log "${RED}File genesis.json non trovato${RESET}"
        exit 1
    fi
    
    if [ -f ./uomi ]; then
        sudo_command cp ./uomi $BINARY_PATH
    elif [ -f ./target/release/uomi ]; then
        sudo_command cp ./target/release/uomi $BINARY_PATH
    else
        stop_spinner "fail"
        log "${RED}Binary uomi non trovato${RESET}"
        exit 1
    fi
    
    sudo_command chmod +x $BINARY_PATH
    stop_spinner "success"
}

# Inserimento chiavi validatore
insert_validator_keys() {
    start_spinner "Inserimento chiavi validatore..."
    
    local attempts=0
    local max_attempts=30
    
    while ! curl -s -H "Content-Type: application/json" \
        -d '{"id":1, "jsonrpc":"2.0", "method": "system_health", "params":[]}' \
        http://localhost:$DEFAULT_RPC_PORT > /dev/null; do
        sleep 2
        ((attempts++))
        if [ $attempts -ge $max_attempts ]; then
            stop_spinner "fail"
            log "${RED}Timeout attesa nodo${RESET}"
            exit 1
        fi
    done

    # Inserisci la chiave Sr25519 per BABE, IMON, uomi, ipfs
    local success=true
    for key_type in babe imon uomi ipfs; do
        if ! curl -s -H "Content-Type: application/json" \
            -d "{\"id\":1, \"jsonrpc\":\"2.0\", \"method\":\"author_insertKey\", \"params\":[\"${key_type}\", \"$(cat $TMP_DIR/validator_phrase)\", \"$(cat $TMP_DIR/validator_public)\"]}" \
            http://localhost:$DEFAULT_RPC_PORT > /dev/null; then
            success=false
            break
        fi
    done

    # Inserisci la chiave Ed25519 per GRANDPA
    if [ "$success" = true ]; then
        if ! curl -s -H "Content-Type: application/json" \
            -d "{\"id\":1, \"jsonrpc\":\"2.0\", \"method\":\"author_insertKey\", \"params\":[\"gran\", \"$(cat $TMP_DIR/validator_phrase)\", \"$(cat $TMP_DIR/validator_ed_public)\"]}" \
            http://localhost:$DEFAULT_RPC_PORT > /dev/null; then
            success=false
        fi
    fi

    if [ "$success" = true ]; then
    # Ruota le chiavi
        if curl -s -H "Content-Type: application/json" \
            -d '{"id":1, "jsonrpc":"2.0", "method": "author_rotateKeys", "params":[]}' \
            http://localhost:$DEFAULT_RPC_PORT > "$TMP_DIR/rotate_key.json"; then
            if jq -e '.result' "$TMP_DIR/rotate_key.json" > "$TMP_DIR/rotate_key"; then
                stop_spinner "success"
            else
                stop_spinner "fail"
                log "${RED}Errore: rotazione chiavi non riuscita${RESET}"
                exit 1
            fi
        else
            stop_spinner "fail"
            log "${RED}Errore nella rotazione delle chiavi${RESET}"
            exit 1
        fi
    fi
}

# Backup chiavi validatore
backup_validator_keys() {
    local backup_dir="$HOME/uomi_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir" || {
        log "${RED}Errore nella creazione della directory di backup${RESET}"
        exit 1
    }
    chmod 700 "$backup_dir"
    
    cp "$TMP_DIR"/* "$backup_dir/" || {
        log "${RED}Errore nella copia dei file di backup${RESET}"
        exit 1
    }
    chmod 600 "$backup_dir"/*
    
    if [ ! -f "$backup_dir/validator_phrase" ]; then
        log "${RED}Backup incompleto${RESET}"
        exit 1
    fi
    
    log "${GREEN}✓ Backup chiavi salvato in: $backup_dir${RESET}"
    log "${YELLOW}IMPORTANTE: Salva queste chiavi in un posto sicuro!${RESET}"
}

# Stampa informazioni validatore
print_validator_info() {
    echo "\n${YELLOW}════════ INFORMAZIONI VALIDATORE ════════${RESET}"
    echo "${CYAN}Nome: $1${RESET}"
    echo "${CYAN}Secret phrase:     $(cat $TMP_DIR/validator_phrase)${RESET}"
    echo "${CYAN}Sr25519 Public key (BABE/IMON/UOMI/IPFS): $(cat $TMP_DIR/validator_public)${RESET}"
    echo "${CYAN}Ed25519 Public key (GRANDPA):   $(cat $TMP_DIR/validator_ed_public)${RESET}"
    echo "${CYAN}Chiave rotazione:  $(cat $TMP_DIR/rotate_key)${RESET}"
    echo "${YELLOW}═══════════════════════════════════════${RESET}\n"
}

# Installazione nodo
install_node() {
    local node_type
    case $1 in
        1) node_type="full" ;;
        2) node_type="archive" ;;
        3) node_type="validator" ;;
        *) log "${RED}Tipo nodo non valido${RESET}"; exit 1 ;;
    esac
    
    local node_name=$2
    
    check_system_requirements
    create_secure_environment
    install_dependencies
    setup_node
    
    if [ "$node_type" = "validator" ]; then
        setup_validator_keys "$node_name"
    fi
    
    create_service_file "$node_type" "$node_name"
    
    sudo_command systemctl daemon-reload
    sudo_command systemctl enable uomi.service
    sudo_command systemctl start uomi.service
    
    if [ "$node_type" = "validator" ]; then
        insert_validator_keys
        backup_validator_keys
        print_validator_info "$node_name"
    fi
    
    log "${GREEN}Nodo $node_type installato e avviato con successo${RESET}"
}

# Rimozione nodo
remove_node() {
    log "${YELLOW}Rimozione nodo...${RESET}"
    
    if [ -f $SERVICE_FILE ]; then
        sudo_command systemctl stop uomi.service
        sudo_command systemctl disable uomi.service
        sudo_command rm $SERVICE_FILE
    fi
    
    if [ -d $NODE_PATH ]; then
        sudo_command rm -rf $NODE_PATH
    fi
    
    if [ -f $BINARY_PATH ]; then
        sudo_command rm $BINARY_PATH
    fi
    
    if [ -f $CHAIN_SPEC_PATH ]; then
        sudo_command rm $CHAIN_SPEC_PATH
    fi
    
    log "${GREEN}✓ Nodo rimosso con successo${RESET}"
}

# Stato nodo
show_status() {
    if [ -f $SERVICE_FILE ]; then
        systemctl status uomi.service
    else
        log "${YELLOW}Nodo non installato${RESET}"
    fi
}

# Pulizia
cleanup() {
    if [ -d "$TMP_DIR" ]; then
        find "$TMP_DIR" -type f -exec shred -u {} \;
        rm -rf "$TMP_DIR"
    fi
}

# Menu principale
show_menu() {
    echo  "${CYAN}Scegli un'opzione:${RESET}"
    echo  "1) ${GREEN}Installa nodo completo${RESET}"
    echo  "2) ${GREEN}Installa nodo archivio${RESET}"
    echo  "3) ${GREEN}Installa nodo validatore${RESET}"
    echo  "4) ${RED}Rimuovi nodo${RESET}"
    echo  "5) ${YELLOW}Mostra stato${RESET}"
    echo  "6) ${BLUE}Esci${RESET}\n"
}



# Main
main() {
    # Arte ASCII di benvenuto
    echo  "\n
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░██╗░░░██╗░█████╗░███╗░░░███╗██╗░
░██║░░░██║██╔══██╗████╗░████║██║░
░██║░░░██║██║░░██║██╔████╔██║██║░
░██║░░░██║██║░░██║██║╚██╔╝██║██║░
░╚██████╔╝╚█████╔╝██║░╚═╝░██║██║░
░░╚═════╝░░╚════╝░╚═╝░░░░░╚═╝╚═╝░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
\n"

    trap cleanup EXIT
    
    while true; do
        show_menu
        read -p "Scelta: " choice
        case $choice in
            1|2|3)
                read -p "Nome nodo: " node_name
                install_node $choice "$node_name"
                ;;
            4)
                remove_node
                ;;
            5)
                show_status
                ;;
            6)
                exit 0
                ;;
            *)
                echo  "${RED}Scelta non valida${RESET}"
                ;;
        esac
    done
}

main

