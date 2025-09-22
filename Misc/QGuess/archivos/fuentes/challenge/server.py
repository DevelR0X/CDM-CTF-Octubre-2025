from qiskit import QuantumCircuit, transpile
from scipy.stats import binomtest
from qiskit_aer import Aer
import ast
import os

FLAG = os.getenv("GZCTF_FLAG", "CDM{73571nG_fl4g!}")

class QGuess:
    def __init__(self):
        self.backend = Aer.get_backend("qasm_simulator")
    
    def generate_circuit(self, instructions: str):
        circuit = QuantumCircuit(2)

        circuit.h(0)
        
        instructions = instructions.split(";")
        
        for instr in instructions:
            try:
                gate, params = instr.split(":")
            except:
                print("Cada instrucción debe tener el formato <puerta>:<parametros>")
                return None
            
            try:
                params = [ int(p) for p in params.split(",") ]
            except:
                print("Los parámetros de la puerta cuántica deben ser enteros.")
                return None

            if len(params) == 1:
                if   gate == "H": circuit.h(params[0])
                elif gate == "S": circuit.s(params[0])
                elif gate == "T": circuit.t(params[0])
                elif gate == "X": circuit.x(params[0])
                else:
                    print("La puerta cuántica proporcionada no es válida.")
                    return None

            if len(params) == 2:
                if   gate == "CX": circuit.cx(params[0], params[1])
                elif gate == "CY": circuit.cy(params[0], params[1])
                elif gate == "CZ": circuit.cz(params[0], params[1])
                else:
                    print("La puerta cuántica proporcionada no es válida.")
                    return None

        circuit.measure_all()

        return transpile(circuit, self.backend)

    def validate_entropy(self, bits):
        binomial_test = binomtest(bits.count("0"), n = len(bits), p = 0.5, alternative = 'two-sided')

        return not binomial_test.pvalue < 0.01
        
    def extract_numbers(self, bits):
        return [int(''.join(bits[i : i + 8]), 2) for i in range(0, len(bits), 8)]

    def run_game(self, instructions):
        circuit = self.generate_circuit(instructions)

        if not circuit:
            return None

        results = self.backend.run(circuit, shots = 64, memory = True).result().get_memory()

        player_bits, server_bits = zip(*[(r[0], r[1]) for r in results])

        if not self.validate_entropy(server_bits):
            print("Los bits del servidor no son lo suficientemente aleatorios.")
            return None

        server_numbers = self.extract_numbers(server_bits)
        player_numbers = self.extract_numbers(player_bits)
            
        return server_numbers, player_numbers

def main():
    guess = QGuess()

    menu = """
    Entre humo de neón y dados fotónicos,
    te sientas frente a una mesa olvidada:
    QGuess.

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

    instructions = input("Coloca tus fichas cuánticas: añade compuertas al circuito (Ej: X:0;H:1): ")

    numbers = guess.run_game(instructions)

    if not numbers:
        return

    server_numbers, player_numbers = numbers

    print(f"El qubit 1 deja ver sus números como cartas marcadas: {player_numbers}")

    while True:
        guess_numbers = ast.literal_eval(input("Haz tu apuesta: ingresa tu lista de 8 números: "))

        if not isinstance(guess_numbers, list) or not all(isinstance(n, int) for n in guess_numbers):
            print("Debes ingresar una lista de números, como [1, 2, 3]")
            continue

        if len(guess_numbers) != 8 or any(n < 0 or n > 255 for n in guess_numbers):
            print("Debes especificar 8 números entre 0 y 255.")
            continue

        break

    if guess_numbers == server_numbers:
        print(
            f"Conquista limpia.\n"
            f"Esta mesa sirvió a Pharmatek en otro tiempo... pero hoy, la ciudad la recuerda como tuya.\n"
            f"Fragmento de Bóveda: {FLAG}"
        )
    else:
        print(
            "El candado no cede. El circuito respondió con silencio.\n"
            "Los números eran:\n"
            f"{server_numbers}\n\n"
        )

if __name__ == "__main__":
    main()
