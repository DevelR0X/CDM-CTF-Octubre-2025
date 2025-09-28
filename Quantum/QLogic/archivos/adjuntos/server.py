from qiskit import QuantumCircuit, transpile
from qiskit_aer import Aer

from itertools import product
import os

FLAG = os.getenv("GZCTF_FLAG", "CDM{73571nG_fl4g!}")

class QLogic:
    def __init__(self):
        self.backend = Aer.get_backend("qasm_simulator")

        self.one_qubit = {
            "H": QuantumCircuit.h, "X": QuantumCircuit.x
        }

        self.two_qubit = {
            "CX": QuantumCircuit.cx,
        }

        self.three_qubit = {
            "CCX": QuantumCircuit.ccx,
        }

        self.params_mapper = {
            1: self.one_qubit,
            2: self.two_qubit,
            3: self.three_qubit,
        }

    def generate_circuit(self, gates, a, b):
        qc = QuantumCircuit(3)

        if a: qc.x(0)
        if b: qc.x(1)

        for instr in gates:
            try:
                gate, raw = instr.split(":")
                params = [int(x) for x in raw.split(",")] if raw else []
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

    def check_circuit(self, gates):
        for a, b in product([0, 1], repeat = 2):
            qc = self.generate_circuit(gates, a, b)
            if qc is None:
                return False

            out2, out1, out0 = self.backend.run(qc, shots = 1, memory = True).result().get_memory()[0]

            if not (int(out0) == (a ^ b) and int(out1) == (a & b) and int(out2) == (not (a & b))):
                return False
        return True

def main():
    game = QLogic()
    menu = """
    Entre chatarra y neón oxidado, una mesa de pruebas sigue activa.
    Su lógica es simple, pero su diseño exige precisión: reproducir
    XOR, AND y NAND en un mismo circuito cuántico.

    Si tu diseño es aceptado, la mesa revelará un código oculto de
    acceso. Si fallas, sólo verás ruido.
    """
    print(menu)

    while True:
        gates_raw = input("Coloca tus compuertas: ").strip()
        gates = [g for g in gates_raw.split(";") if g]

        try:
            if game.check_circuit(gates):
                print("Diseño aceptado. Canal abierto. Código de acceso:", FLAG)
            else:
                print("La mesa rechaza tu diseño. Los resultados no coinciden…")
        
        except Exception as e:
            print("Error en el circuito:", e)

if __name__ == "__main__":
    main()
