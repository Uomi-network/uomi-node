#!/bin/bash

# Colori per output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

# Variabili
BINARY_PATH=""
GENESIS_PATH="./genesis.json"
TMP_DIR=$(mktemp -d)
chmod 700 $TMP_DIR

# Funzione di logging
log() {
    echo "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${RESET} $1"
}

# Funzione di cleanup
cleanup() {
    if [ -d "$TMP_DIR" ]; then
        find "$TMP_DIR" -type f -exec shred -u {} \;
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT

# Installa dipendenze necessarie
install_dependencies() {
    log "Verifico/installo dipendenze..."
    
    if ! command -v jq >/dev/null 2>&1; then
        log "Installo jq..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update && sudo apt-get install -y jq
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y jq
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y jq
        else
            echo "${RED}Impossibile installare jq. Installa manualmente jq e riprova.${RESET}"
            exit 1
        fi
    fi
}

# Verifica presenza file necessari
check_requirements() {
    log "Verifico i requisiti..."
    
    # Verifica e installa dipendenze
    install_dependencies
    
    # Verifica presenza binary
    if [ -f "./uomi" ]; then
        BINARY_PATH="./uomi"
        log "Binary trovato in ./uomi"
    elif [ -f "./target/release/uomi" ]; then
        BINARY_PATH="./target/release/uomi"
        log "Binary trovato in ./target/release/uomi"
    else
        echo "${RED}Binary non trovato. Cercato in:${RESET}"
        echo "${RED}- ./uomi${RESET}"
        echo "${RED}- ./target/release/uomi${RESET}"
        exit 1
    fi
    
    # Verifica permessi di esecuzione sul binary
    if [ ! -x "$BINARY_PATH" ]; then
        log "Aggiungo permessi di esecuzione al binary..."
        chmod +x "$BINARY_PATH" || {
            echo "${RED}Impossibile rendere eseguibile il binary${RESET}"
            exit 1
        }
    fi
    
    # Verifica presenza genesis file
    if [ ! -f "$GENESIS_PATH" ]; then
        echo "${RED}File genesis non trovato in $GENESIS_PATH${RESET}"
        exit 1
    fi
}

# Genera le chiavi per il validatore
generate_keys() {
    log "Generazione chiavi..."
    
    # Genera chiave Sr25519 per BABE e IMON
    $BINARY_PATH key generate --scheme Sr25519 --output-type json > "$TMP_DIR/validator.json"
    local sr25519_phrase=$(jq -r .secretPhrase "$TMP_DIR/validator.json")
    local sr25519_public=$(jq -r .publicKey "$TMP_DIR/validator.json")
    local ss58_address=$(jq -r .ss58Address "$TMP_DIR/validator.json")
    
    # Genera chiave Ed25519 per GRANDPA dalla stessa frase
    $BINARY_PATH key inspect --scheme Ed25519 "$sr25519_phrase" --output-type json > "$TMP_DIR/validator_ed.json"
    local ed25519_public=$(jq -r .publicKey "$TMP_DIR/validator_ed.json")
    
    # Salva le chiavi in file separati
    echo "$sr25519_phrase" > "$TMP_DIR/phrase"
    echo "$sr25519_public" > "$TMP_DIR/sr25519_public"
    echo "$ed25519_public" > "$TMP_DIR/ed25519_public"
    echo "$ss58_address" > "$TMP_DIR/ss58_address"
    
    echo "CHIAVI GENERATE:"
    echo "${GREEN}Secret Phrase:${RESET} $sr25519_phrase"
    echo "${GREEN}SS58 Address:${RESET} $ss58_address"
    echo "${GREEN}Sr25519 Public (BABE/IMON):${RESET} $sr25519_public"
    echo "${GREEN}Ed25519 Public (GRANDPA):${RESET} $ed25519_public"
}



# Funzione principale
main() {
    echo "${YELLOW}=== Genesis Admin Tool ===${RESET}\n"
    
    check_requirements
    generate_keys
    
    echo "\n${GREEN}Completato! Il file genesis è stato aggiornato con le nuove chiavi.${RESET}"
    echo "${YELLOW}IMPORTANTE: Salva la Secret Phrase in un posto sicuro!${RESET}"
}

main