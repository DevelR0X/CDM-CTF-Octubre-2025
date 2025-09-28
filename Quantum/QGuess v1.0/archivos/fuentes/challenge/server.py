from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer
import os, ast

FLAG = os.getenv("GZCTF_FLAG", "CDM{73571nG_fl4g!}")

class QGuess:
    def __init__(self):
        self.backend = Aer.get_backend("qasm_simulator")
        
        self.one_qubit = {
            "H": QuantumCircuit.h, "X": QuantumCircuit.x,
            "Y": QuantumCircuit.y, "Z": QuantumCircuit.z
        }
        self.two_qubit = {
            "CX": QuantumCircuit.cx, "CY": QuantumCircuit.cy,
            "CZ": QuantumCircuit.cz
        }

        self.params_mapper = {
            1: self.one_qubit,
            2: self.two_qubit
        }

    def generate_circuit(self, instructions: str):
        qc = QuantumCircuit(2)
        qc.h(0)

        for instr in instructions.split(";"):
            try:
                gate, raw_params = instr.split(":")
                params = [ int(x) for x in raw_params.split(",") ]
            except:
                print("Cada instrucción debe tener el formato <puerta>:<parametros>")
                return None

            if any(idx >= qc.num_qubits for idx in params):
                print(f"Cada índice debe ser menor a {qc.num_qubits}")
                return None

            apply_gate = self.params_mapper.get(len(params), {}).get(gate)
            
            if not apply_gate:
                print(f"La puerta cuántica '{gate}' proporcionada no es válida.")
                return None
            
            apply_gate(qc, *params)

        qc.measure_all()
        
        return transpile(qc, self.backend)

    def run_game(self, instructions: str):
        qc = self.generate_circuit(instructions)
        
        if qc is None:
            return None

        outcome = self.backend.run(qc, shots = 64, memory = True).result().get_memory()
        
        server, player = zip(*[(res[0], res[1]) for res in outcome])

        server_numbers = [int("".join(server[i : i + 8]), 2) for i in range(0, len(server), 8)]
        player_numbers = [int("".join(player[i : i + 8]), 2) for i in range(0, len(player), 8)]

        return server_numbers, player_numbers


def main():
    game = QGuess()

    menu = """
    Entre humo de neón y dados fotónicos,
    te sientas frente a una mesa olvidada:
    QGuess v1.0.

    Aquí las reglas son simples pero traicioneras:

    - Un circuito cuántico de 2 qubits gira como ruleta.
    - Ambos generan 8 números entre 0 y 255.
    - Tú sólo podrás ver la secuencia del qubit 1,
    pero tu desafío es adivinar la del qubit 0.

    Los crupieres del Campo dicen que quien acierte
    recibe más que fichas: un Fragmento de Bóveda.

    ¿Podrás leer en el caos?
    """
    print(menu)

    instr = input("Coloca tus fichas cuánticas: añade compuertas al circuito (Ej: X:0;H:1): ")
    result = game.run_game(instr)

    if result is None:
        return

    server_nums, player_nums = result

    print(f"El qubit 1 deja ver sus números como cartas marcadas: {player_nums}")

    while True:
        try:
            guess = ast.literal_eval(input("Haz tu apuesta: ingresa tu lista de 8 números: "))
        except Exception:
            print("Debes ingresar una lista de números, como [1, 2, 3]")
            continue

        if not (isinstance(guess, list) and all(isinstance(n, int) for n in guess)):
            print("Debes ingresar una lista de números")
            continue

        if len(guess) != 8 or any(n < 0 or n > 255 for n in guess):
            print("Debes especificar 8 números entre 0 y 255")
            continue
        break

    if guess == server_nums:
        print(
            "Conquista limpia.\n"
            "Esta mesa sirvió a Pharmatek en otro tiempo... pero hoy, la ciudad la recuerda como tuya.\n"
            f"Fragmento de Bóveda: {FLAG}"
        )
    else:
        print(
            "El candado no cede. El circuito respondió con silencio.\n"
            "Los números eran:\n"
            f"{server_nums}\n\n"
        )

if __name__ == "__main__":
    main()
