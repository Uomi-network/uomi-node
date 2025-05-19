# UOMI ENGINE

This is the main pallet used by Uomi Network to manage the execution of AI Agents.

## Development

### Testing

To test, run:

```bash
cargo test -- --show-output # NOTE: --show-output is optional and permits to see the output of all the logs executed during the tests
```

### Benchmarking

To benchmark, run:

```bash
cargo test --features runtime-benchmarks
```

## Opoc actual description (PSEUDO-CODE)

```txt
opoc_assignments_of_level_1 = 10 # NUMERO DI NODI CHE DEVONO ESEGUIRE L'OPERAZIONE CON ACCORDO ASSOLUTO, PRIMA DI SCALARE AL L2
opoc_assignment_count = N # NUMERO DI NODI CHE HANNO RICEVUTO L'ASSEGNAZIONE DELLA RICHIESTA

# Avvio opoc L0
# ---------------------------------------------------------------------------------------------------

SE opoc_assignment_count == 0 ALLORA
  ASSEGNO LA RICHIESTA AD UN NODO A CASO (DANDO PRECEDENZA A QUELLI LIBERI)
FINE

# Controllo opoc L0 | Avvio opoc L1
# ---------------------------------------------------------------------------------------------------

SE opoc_assignment_count == 1 ALLORA
  outputs, validators_not_completed, validators_in_timeout = opoc_get_outputs()

  SE validators_not_completed > 0 ALLORA
    BREAK
  FINE

  SE validators_in_timeout > 0 ALLORA
    APPLICO PENALITA PER TIMEOUT
    RIASSEGNO LA RICHIESTA AD UN NODO A CASO (DANDO PRECEDENZA A QUELLI LIBERI)
    BREAK
  FINE

  SE opoc_assignments_of_level_1 <= 1
    CONCLUDO ESECUZIONE
    BREAK
  FINE

  ASSEGNO LA RICHIESTA A (opoc_assignments_of_level_1 - 1) NODI A CASO (ESCLUSI QUELLI CHE HANNO GIA' ESEGUITO)
FINE

# Controllo opoc L1 | Avvio opoc L2
# ---------------------------------------------------------------------------------------------------

SE opoc_assignment_count == opoc_assignments_of_level_1 ALLORA
  outputs, validators_not_completed, validators_in_timeout = opoc_get_outputs()

  SE validators_in_timeout > 0 ALLORA
    PER OGNI validators_in_timeout
      APPLICO PENALITA PER TIMEOUT
    FINE

    RIASSEGNO LA RICHIESTA A validators_in_timeout NODI A CASO (ESCLUSI QUELLI CHE HANNO GIA' ESEGUITO O CHE STANNO ESEGUENDO)
    BREAK
  FINE

  SE validators_not_completed > 0 ALLORA
    BREAK
  FINE

  final_output = CONTROLLO CHE TUTTI GLI OUTPUTS SIANO UGUALI

  SE final_output == True ALLORA
    CONCLUDO ESECUZIONE
    BREAK
  FINE

  RIASSEGNO LA RICHIESTA A 2/3+1 DEI NODI DELLA CHAIN (TOLTI QUELLI CHE HANNO GIA' ESEGUITO)
FINE

# Controllo opoc L2
# ---------------------------------------------------------------------------------------------------

SE opoc_assignment_count > opoc_assignments_of_level_1 ALLORA
  outputs, validators_not_completed, validators_in_timeout = opoc_get_outputs()

  SE validators_not_completed > 0 ALLORA
    BREAK
  FINE

  SE validators_in_timeout > 0 ALLORA
    PER OGNI validators_in_timeout
      APPLICO PENALITA PER TIMEOUT
    FINE
  FINE

  final_output = OUTPUT DI MAGGIORANZA

  PER OGNI validator CHE HA DATO UN OUTPUT DIVERSO DA final_output
    APPLICO PENALITA PER OUTPUT DIVERSO
  FINE

  CONCLUDO ESECUZIONE
FINE
```

## Opoc new version description (PSEUDO-CODE)

```txt
opoc_assignments_of_level_1 = 10 # NUMERO DI NODI CHE DEVONO ESEGUIRE L'OPERAZIONE CON ACCORDO ASSOLUTO, PRIMA DI SCALARE AL L2
opoc_assignment_count = N # NUMERO DI NODI CHE HANNO RICEVUTO L'ASSEGNAZIONE DELLA RICHIESTA

# Avvio opoc L0
# ---------------------------------------------------------------------------------------------------

SE opoc_assignment_count == 0 ALLORA
  ASSEGNO LA RICHIESTA AD UN NODO A CASO (DANDO PRECEDENZA A QUELLI LIBERI)
FINE

# Controllo opoc L0 | Avvio opoc L1
# ---------------------------------------------------------------------------------------------------

SE opoc_assignment_count == 1 ALLORA
  outputs, validators_not_completed, validators_in_timeout = opoc_get_outputs()

  SE validators_not_completed > 0 ALLORA
    BREAK
  FINE

  SE validators_in_timeout > 0 ALLORA
    APPLICO PENALITA PER TIMEOUT
    RIASSEGNO LA RICHIESTA AD UN NODO A CASO (DANDO PRECEDENZA A QUELLI LIBERI)
    BREAK
  FINE

  SE outputs[0] == empty ALLORA
    APPLICO PENALITA PER TIMEOUT
    RIASSEGNO LA RICHIESTA AD UN NODO A CASO (DANDO PRECEDENZA A QUELLI LIBERI) # NOTE: Dovremo tenere un contatore per annullare la richiesta se viene riassegnata troppe volte.
    BREAK
  FINE

  SE opoc_assignments_of_level_1 <= 1
    CONCLUDO ESECUZIONE
    BREAK
  FINE

  ASSEGNO LA RICHIESTA A (opoc_assignments_of_level_1 - 1) NODI A CASO (ESCLUSI QUELLI CHE HANNO GIA' ESEGUITO)
FINE

# Controllo opoc L1 | Avvio opoc L2
# ---------------------------------------------------------------------------------------------------

SE opoc_assignment_count == opoc_assignments_of_level_1 ALLORA
  outputs, validators_not_completed, validators_in_timeout = opoc_get_outputs()

  SE validators_in_timeout > 0 ALLORA
    PER OGNI validators_in_timeout
      APPLICO PENALITA PER TIMEOUT
    FINE

    RIASSEGNO LA RICHIESTA A validators_in_timeout NODI A CASO (ESCLUSI QUELLI CHE HANNO GIA' ESEGUITO O CHE STANNO ESEGUENDO)
    BREAK
  FINE

  SE any(outputs) == empty ALLORA
    PER OGNI output CHE E' EMPTY
      APPLICO PENALITA PER TIMEOUT
      RIASSEGNO LA RICHIESTA AD UN NODO A CASO # NOTE: Dovremo tenere un contatore per annullare la richiesta se viene riassegnata troppe volte.
    FINE
    BREAK
  FINE

  SE validators_not_completed > 0 ALLORA
    BREAK
  FINE

  final_output = CONTROLLO CHE TUTTI GLI OUTPUTS SIANO UGUALI

  SE final_output == True ALLORA
    CONCLUDO ESECUZIONE
    BREAK
  FINE

  RIASSEGNO LA RICHIESTA A 2/3+1 DEI NODI DELLA CHAIN (TOLTI QUELLI CHE HANNO GIA' ESEGUITO)
FINE

# Controllo opoc L2
# ---------------------------------------------------------------------------------------------------

SE opoc_assignment_count > opoc_assignments_of_level_1 ALLORA
  outputs, validators_not_completed, validators_in_timeout = opoc_get_outputs()

  SE validators_not_completed > 0 ALLORA
    BREAK
  FINE

  SE validators_in_timeout > 0 ALLORA
    PER OGNI validators_in_timeout
      APPLICO PENALITA PER TIMEOUT
    FINE
  FINE

  SE any(outputs) == empty ALLORA
    PER OGNI output CHE E' EMPTY
      APPLICO PENALITA PER TIMEOUT
    FINE
    BREAK
  FINE

  final_output = OUTPUT DI MAGGIORANZA ESCLUDENDO I VALORI EMPTY

  PER OGNI validator CHE HA DATO UN OUTPUT DIVERSO DA final_output
    APPLICO PENALITA PER OUTPUT DIVERSO
  FINE

  CONCLUDO ESECUZIONE
FINE
```
