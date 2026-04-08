--- cybersecurity_attack_model.py (原始)


+++ cybersecurity_attack_model.py (修改后)
#!/usr/bin/env python3
"""
Modelo Matemático Formal para Simulación y Análisis de Ataques Informáticos
Basado en Teoría de la Computación: Sistemas de Transición de Estados (STS)

Autor: Cybersecurity Research Team
Descripción: Este modelo representa formalmente cómo un atacante se mueve
             a través de una red utilizando sistemas de transición de estados.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, FrozenSet
from enum import Enum, auto
from collections import defaultdict
import random
import math
from functools import lru_cache


# ============================================================================
# DEFINICIONES FORMALES - TEORÍA DE LA COMPUTACIÓN
# ============================================================================

class PrivilegeLevel(Enum):
    """Niveles de privilegio en el sistema"""
    NONE = 0
    USER = 1
    ADMIN = 2
    ROOT = 3
    SYSTEM = 4

    def __gt__(self, other):
        if isinstance(other, PrivilegeLevel):
            return self.value > other.value
        return NotImplemented

    def __ge__(self, other):
        if isinstance(other, PrivilegeLevel):
            return self.value >= other.value
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, PrivilegeLevel):
            return self.value < other.value
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, PrivilegeLevel):
            return self.value <= other.value
        return NotImplemented


class NodeType(Enum):
    """Tipos de nodos en la red"""
    WORKSTATION = auto()
    SERVER = auto()
    DATABASE = auto()
    FIREWALL = auto()
    ROUTER = auto()
    IOT_DEVICE = auto()


class AttackVector(Enum):
    """Vectores de ataque posibles"""
    PHISHING = auto()
    EXPLOIT = auto()
    BRUTE_FORCE = auto()
    SQL_INJECTION = auto()
    XSS = auto()
    MAN_IN_THE_MIDDLE = auto()
    ZERO_DAY = auto()
    CREDENTIAL_STUFFING = auto()
    PRIVILEGE_ESCALATION = auto()
    LATERAL_MOVEMENT = auto()


@dataclass(frozen=True)
class SecurityProperty:
    """Propiedades de seguridad del nodo (CID: Confidencialidad, Integridad, Disponibilidad)"""
    confidentiality: float = 1.0  # 0.0 = comprometida, 1.0 = intacta
    integrity: float = 1.0
    availability: float = 1.0
    authentication_strength: float = 1.0

    def is_compromised(self, threshold: float = 0.5) -> bool:
        """Determina si el nodo está comprometido"""
        return min(self.confidentiality, self.integrity, self.availability) < threshold


@dataclass(frozen=True)
class NetworkNode:
    """
    Nodo de la red en el modelo formal

    Representa un estado parcial del sistema
    """
    node_id: str
    node_type: NodeType
    privileges: PrivilegeLevel = PrivilegeLevel.NONE
    security_properties: SecurityProperty = field(default_factory=SecurityProperty)
    vulnerabilities: FrozenSet[str] = field(default_factory=frozenset)
    is_compromised: bool = False
    access_probability: float = 0.0

    def __hash__(self):
        return hash(self.node_id)


@dataclass(frozen=True)
class AttackAction:
    """
    Acción de ataque en el sistema de transición

    Representa una transición τ ∈ T en el STS
    """
    action_id: str
    attack_vector: AttackVector
    source_node: str
    target_node: str
    success_probability: float
    cost: float
    time_required: float
    required_privileges: PrivilegeLevel = PrivilegeLevel.NONE
    effect_description: str = ""

    def __hash__(self):
        return hash((self.action_id, self.source_node, self.target_node))


# ============================================================================
# SISTEMA DE TRANSICIÓN DE ESTADOS (STS) FORMAL
# ============================================================================

@dataclass
class StateTransitionSystem:
    """
    Sistema de Transición de Estados Formal

    Definición matemática: STS = (S, S₀, T, →, L)
    donde:
    - S: Conjunto finito de estados
    - S₀ ⊆ S: Conjunto de estados iniciales
    - T: Conjunto de etiquetas de transición (acciones de ataque)
    - → ⊆ S × T × S: Relación de transición
    - L: S × P(AP) función de etiquetado (AP = proposiciones atómicas)
    """

    # S: Conjunto de estados (cada estado es una configuración de la red)
    states: Set[FrozenSet[Tuple[str, any]]] = field(default_factory=set)

    # S₀: Estado inicial
    initial_state: FrozenSet[Tuple[str, any]] = field(default_factory=frozenset)

    # T: Conjunto de acciones de ataque disponibles
    attack_actions: Set[AttackAction] = field(default_factory=set)

    # Grafo de transiciones: estado_origen -> [(acción, estado_destino)]
    transitions: Dict[FrozenSet, List[Tuple[AttackAction, FrozenSet]]] = field(
        default_factory=lambda: defaultdict(list)
    )

    # Proposiciones atómicas (hechos sobre el estado)
    atomic_propositions: Set[str] = field(default_factory=set)

    # Etiquetado de estados
    labeling: Dict[FrozenSet, Set[str]] = field(default_factory=dict)

    def state_to_frozen(self, network_state: Dict[str, NetworkNode]) -> FrozenSet:
        """Convierte un estado de red a una forma inmutable (hashable)"""
        return frozenset([
            (node_id,
             node.node_type,
             node.privileges,
             node.is_compromised,
             node.security_properties)
            for node_id, node in sorted(network_state.items())
        ])

    def add_transition(self,
                       from_state: FrozenSet,
                       action: AttackAction,
                       to_state: FrozenSet):
        """Añade una transición al sistema"""
        self.transitions[from_state].append((action, to_state))
        self.states.add(from_state)
        self.states.add(to_state)

    def get_reachable_states(self, initial: FrozenSet) -> Set[FrozenSet]:
        """Calcula todos los estados alcanzables desde el estado inicial"""
        reachable = {initial}
        queue = [initial]

        while queue:
            current = queue.pop(0)
            for action, next_state in self.transitions.get(current, []):
                if next_state not in reachable:
                    reachable.add(next_state)
                    queue.append(next_state)

        return reachable

    def compute_attack_paths(self,
                            initial: FrozenSet,
                            goal_predicate) -> List[List[Tuple[AttackAction, FrozenSet]]]:
        """
        Encuentra todos los caminos de ataque desde el estado inicial
        hasta estados que satisfacen el predicado objetivo
        """
        paths = []

        def dfs(current: FrozenSet, path: List[Tuple[AttackAction, FrozenSet]], visited: Set[FrozenSet]):
            if goal_predicate(current):
                paths.append(path.copy())
                return

            if current in visited:
                return

            visited.add(current)

            for action, next_state in self.transitions.get(current, []):
                path.append((action, next_state))
                dfs(next_state, path, visited)
                path.pop()

            visited.remove(current)

        dfs(initial, [], set())
        return paths


# ============================================================================
# MODELO DE RED Y SIMULADOR DE ATAQUES
# ============================================================================

class CyberAttackSimulator:
    """
    Simulador de Ataques Informáticos basado en STS

    Implementa la semántica operacional del sistema de transición
    """

    def __init__(self):
        self.network: Dict[str, NetworkNode] = {}
        self.sts = StateTransitionSystem()
        self.attack_graph: Dict[str, List[str]] = defaultdict(list)
        self.current_state: Optional[FrozenSet] = None

    def add_node(self,
                 node_id: str,
                 node_type: NodeType,
                 vulnerabilities: List[str] = None,
                 initial_privileges: PrivilegeLevel = PrivilegeLevel.NONE):
        """Añade un nodo a la red"""
        vulns = frozenset(vulnerabilities) if vulnerabilities else frozenset()
        node = NetworkNode(
            node_id=node_id,
            node_type=node_type,
            privileges=initial_privileges,
            vulnerabilities=vulns
        )
        self.network[node_id] = node

    def add_connection(self, source: str, target: str, bidirectional: bool = True):
        """Establece una conexión entre nodos"""
        if source in self.network and target in self.network:
            self.attack_graph[source].append(target)
            if bidirectional:
                self.attack_graph[target].append(source)

    def generate_attack_actions(self) -> Set[AttackAction]:
        """
        Genera automáticamente acciones de ataque basadas en
        la topología de red y vulnerabilidades
        """
        actions = set()
        action_counter = 0

        for node_id, node in self.network.items():
            # Ataques externos hacia nodos no comprometidos
            if not node.is_compromised:
                for vuln in node.vulnerabilities:
                    action = AttackAction(
                        action_id=f"ATTACK_{action_counter}",
                        attack_vector=AttackVector.EXPLOIT,
                        source_node="EXTERNAL",
                        target_node=node_id,
                        success_probability=self._calculate_exploit_probability(vuln),
                        cost=random.uniform(100, 1000),
                        time_required=random.uniform(1, 24),
                        effect_description=f"Explotar vulnerabilidad {vuln}"
                    )
                    actions.add(action)
                    action_counter += 1

            # Movimiento lateral desde nodos comprometidos
            if node.is_compromised or node.privileges > PrivilegeLevel.NONE:
                for neighbor in self.attack_graph[node_id]:
                    neighbor_node = self.network[neighbor]

                    # Escalada de privilegios
                    if node.privileges < PrivilegeLevel.ADMIN:
                        action = AttackAction(
                            action_id=f"LATERAL_{action_counter}",
                            attack_vector=AttackVector.LATERAL_MOVEMENT,
                            source_node=node_id,
                            target_node=neighbor,
                            success_probability=0.7,
                            cost=random.uniform(50, 500),
                            time_required=random.uniform(0.5, 4),
                            required_privileges=node.privileges,
                            effect_description="Movimiento lateral a nodo adyacente"
                        )
                        actions.add(action)
                        action_counter += 1

                    # Escalada local de privilegios
                    if node.privileges < PrivilegeLevel.ROOT and "LOCAL_PRIV_ESC" in node.vulnerabilities:
                        action = AttackAction(
                            action_id=f"PRIVESC_{action_counter}",
                            attack_vector=AttackVector.PRIVILEGE_ESCALATION,
                            source_node=node_id,
                            target_node=node_id,
                            success_probability=0.6,
                            cost=random.uniform(200, 800),
                            time_required=random.uniform(2, 12),
                            required_privileges=PrivilegeLevel.USER,
                            effect_description="Escalada de privilegios local"
                        )
                        actions.add(action)
                        action_counter += 1

        return actions

    def _calculate_exploit_probability(self, vulnerability: str) -> float:
        """Calcula probabilidad de éxito de explotación basada en CVSS simplificado"""
        base_probs = {
            "CVE-2023-XXXX": 0.8,
            "WEAK_PASSWORD": 0.9,
            "UNPATCHED_SERVICE": 0.7,
            "MISCONFIGURATION": 0.6,
            "ZERO_DAY": 0.95,
            "LOCAL_PRIV_ESC": 0.5,
        }
        return base_probs.get(vulnerability, 0.5)

    def apply_action(self,
                     state: Dict[str, NetworkNode],
                     action: AttackAction) -> Dict[str, NetworkNode]:
        """
        Aplica una acción de ataque al estado actual
        Implementa la relación de transición →
        """
        new_state = {nid: node for nid, node in state.items()}
        target = action.target_node

        if target not in new_state:
            return new_state

        # Simular resultado probabilístico
        if random.random() > action.success_probability:
            return new_state  # Fallo del ataque

        node = new_state[target]

        # Aplicar efectos del ataque
        if action.attack_vector == AttackVector.PRIVILEGE_ESCALATION:
            new_priv = PrivilegeLevel(min(node.privileges.value + 1,
                                         PrivilegeLevel.ROOT.value))
            node = NetworkNode(
                node_id=node.node_id,
                node_type=node.node_type,
                privileges=new_priv,
                security_properties=node.security_properties,
                vulnerabilities=node.vulnerabilities,
                is_compromised=True,
                access_probability=min(node.access_probability + 0.3, 1.0)
            )
        elif action.attack_vector in [AttackVector.EXPLOIT, AttackVector.LATERAL_MOVEMENT]:
            node = NetworkNode(
                node_id=node.node_id,
                node_type=node.node_type,
                privileges=max(node.privileges, PrivilegeLevel.USER),
                security_properties=SecurityProperty(
                    confidentiality=max(0, node.security_properties.confidentiality - 0.4),
                    integrity=max(0, node.security_properties.integrity - 0.3),
                    availability=max(0, node.security_properties.availability - 0.2),
                    authentication_strength=max(0, node.security_properties.authentication_strength - 0.5)
                ),
                vulnerabilities=node.vulnerabilities,
                is_compromised=True,
                access_probability=min(node.access_probability + 0.5, 1.0)
            )

        new_state[target] = node
        return new_state

    def build_sts(self, max_depth: int = 5):
        """
        Construye el Sistema de Transición de Estados completo
        hasta una profundidad máxima
        """
        # Estado inicial
        initial_network = {nid: node for nid, node in self.network.items()}
        initial_state = self.sts.state_to_frozen(initial_network)
        self.sts.initial_state = initial_state
        self.current_state = initial_state

        # Generar acciones de ataque
        self.sts.attack_actions = self.generate_attack_actions()

        # BFS para construir el grafo de estados
        from collections import deque
        queue = deque([(initial_state, initial_network, 0)])
        visited = {initial_state}

        while queue:
            current_frozen, current_network, depth = queue.popleft()

            if depth >= max_depth:
                continue

            # Para cada acción posible
            for action in self.sts.attack_actions:
                # Verificar precondiciones
                if action.source_node != "EXTERNAL":
                    source_node = current_network.get(action.source_node)
                    if not source_node or not source_node.is_compromised:
                        continue

                # Aplicar acción múltiples veces para capturar no determinismo
                for _ in range(3):  # 3 intentos para capturar variabilidad
                    next_network = self.apply_action(current_network.copy(), action)
                    next_frozen = self.sts.state_to_frozen(next_network)

                    if next_frozen != current_frozen:
                        self.sts.add_transition(current_frozen, action, next_frozen)

                        if next_frozen not in visited:
                            visited.add(next_frozen)
                            queue.append((next_frozen, next_network, depth + 1))

    def analyze_security_metrics(self) -> Dict[str, any]:
        """
        Calcula métricas de seguridad basadas en el STS
        """
        reachable_states = self.sts.get_reachable_states(self.sts.initial_state)

        # Métrica 1: Número de estados comprometidos
        compromised_count = 0
        for state in reachable_states:
            for _, node_type, privileges, is_compromised, _ in state:
                if is_compromised:
                    compromised_count += 1
                    break

        # Métrica 2: Profundidad máxima de ataque
        max_depth = 0
        for state in reachable_states:
            # Calcular distancia desde estado inicial
            depth = self._calculate_state_depth(state)
            max_depth = max(max_depth, depth)

        # Métrica 3: Probabilidad esperada de compromiso total
        total_compromise_prob = self._calculate_total_compromise_probability(reachable_states)

        # Métrica 4: Tiempo mínimo para compromiso crítico
        min_time_to_critical = self._find_minimum_time_to_critical(reachable_states)

        return {
            "total_states": len(reachable_states),
            "compromised_states": compromised_count,
            "max_attack_depth": max_depth,
            "total_compromise_probability": total_compromise_prob,
            "min_time_to_critical_hours": min_time_to_critical,
            "attack_surface_size": len(self.sts.attack_actions)
        }

    def _calculate_state_depth(self, state: FrozenSet) -> int:
        """Calcula la profundidad del estado en el grafo de transición"""
        if state == self.sts.initial_state:
            return 0

        visited = {self.sts.initial_state}
        queue = [(self.sts.initial_state, 0)]

        while queue:
            current, depth = queue.pop(0)
            for action, next_state in self.sts.transitions.get(current, []):
                if next_state == state:
                    return depth + 1
                if next_state not in visited:
                    visited.add(next_state)
                    queue.append((next_state, depth + 1))

        return -1

    def _calculate_total_compromise_probability(self, states: Set[FrozenSet]) -> float:
        """Calcula la probabilidad de compromiso total de la red"""
        fully_compromised = 0
        for state in states:
            all_compromised = all(is_comp for _, _, _, is_comp, _ in state)
            if all_compromised:
                fully_compromised += 1

        return fully_compromised / len(states) if states else 0.0

    def _find_minimum_time_to_critical(self, states: Set[FrozenSet]) -> float:
        """Encuentra el tiempo mínimo para alcanzar un estado crítico"""
        min_time = float('inf')

        for state in states:
            # Verificar si es estado crítico (al menos un nodo con privilegios ROOT)
            is_critical = any(
                priv == PrivilegeLevel.ROOT or priv == PrivilegeLevel.SYSTEM
                for _, _, priv, _, _ in state
            )

            if is_critical:
                depth = self._calculate_state_depth(state)
                # Estimación rough del tiempo basado en profundidad
                estimated_time = depth * 4.0  # 4 horas promedio por salto
                min_time = min(min_time, estimated_time)

        return min_time if min_time != float('inf') else -1.0

    def find_optimal_attack_path(self) -> List[AttackAction]:
        """
        Encuentra el camino de ataque óptimo (menor costo/tiempo)
        usando búsqueda en el STS
        """
        goal_predicate = lambda state: any(
            priv >= PrivilegeLevel.ROOT for _, _, priv, _, _ in state
        )

        paths = self.sts.compute_attack_paths(self.sts.initial_state, goal_predicate)

        if not paths:
            return []

        # Seleccionar camino con menor costo total
        best_path = None
        best_cost = float('inf')

        for path in paths:
            total_cost = sum(action.cost for action, _ in path)
            if total_cost < best_cost:
                best_cost = total_cost
                best_path = path

        return [action for action, _ in best_path] if best_path else []

    def simulate_attack_scenario(self, num_simulations: int = 100) -> Dict[str, any]:
        """
        Ejecuta múltiples simulaciones de ataque Monte Carlo
        """
        results = {
            "success_rate": 0,
            "avg_time_to_compromise": 0,
            "avg_nodes_compromised": 0,
            "most_targeted_nodes": defaultdict(int),
            "most_successful_attacks": defaultdict(int)
        }

        successful_runs = 0
        total_time = 0
        total_compromised = 0

        for _ in range(num_simulations):
            # Reiniciar estado
            current_network = {nid: node for nid, node in self.network.items()}
            actions_taken = []
            time_elapsed = 0

            # Ejecutar hasta compromiso máximo o límite de pasos
            for step in range(20):
                available_actions = [
                    a for a in self.sts.attack_actions
                    if a.source_node == "EXTERNAL" or
                    (a.source_node in current_network and
                     current_network[a.source_node].is_compromised)
                ]

                if not available_actions:
                    break

                # Seleccionar acción aleatoria ponderada por probabilidad
                action = random.choice(available_actions)
                new_network = self.apply_action(current_network, action)

                if new_network != current_network:
                    actions_taken.append(action)
                    time_elapsed += action.time_required
                    current_network = new_network

                    # Actualizar estadísticas
                    results["most_targeted_nodes"][action.target_node] += 1
                    results["most_successful_attacks"][action.attack_vector.name] += 1

            # Verificar éxito
            compromised_nodes = sum(1 for n in current_network.values() if n.is_compromised)
            total_compromised += compromised_nodes

            if compromised_nodes > 0:
                successful_runs += 1
                total_time += time_elapsed

        results["success_rate"] = successful_runs / num_simulations
        results["avg_time_to_compromise"] = total_time / successful_runs if successful_runs else 0
        results["avg_nodes_compromised"] = total_compromised / num_simulations

        return results


# ============================================================================
# DEMOSTRACIÓN Y CASO DE ESTUDIO
# ============================================================================

def demonstrate_model():
    """
    Demostración completa del modelo con un caso de estudio realista
    """
    print("=" * 80)
    print("MODELO MATEMÁTICO FORMAL PARA ANÁLISIS DE ATAQUES INFORMÁTICOS")
    print("Basado en Sistemas de Transición de Estados (Teoría de la Computación)")
    print("=" * 80)
    print()

    # Crear simulador
    simulator = CyberAttackSimulator()

    # Construir topología de red de ejemplo
    print("[1] Construyendo topología de red...")

    # Nodos de la red
    simulator.add_node("firewall_1", NodeType.FIREWALL,
                      vulnerabilities=["MISCONFIGURATION"])
    simulator.add_node("web_server_1", NodeType.SERVER,
                      vulnerabilities=["CVE-2023-XXXX", "UNPATCHED_SERVICE"])
    simulator.add_node("app_server_1", NodeType.SERVER,
                      vulnerabilities=["WEAK_PASSWORD"])
    simulator.add_node("db_server_1", NodeType.DATABASE,
                      vulnerabilities=["SQL_INJECTION", "WEAK_PASSWORD"])
    simulator.add_node("workstation_1", NodeType.WORKSTATION,
                      vulnerabilities=["PHISHING"])
    simulator.add_node("workstation_2", NodeType.WORKSTATION,
                      vulnerabilities=["UNPATCHED_SERVICE"])
    simulator.add_node("router_1", NodeType.ROUTER,
                      vulnerabilities=["MISCONFIGURATION"])

    # Conexiones de red
    simulator.add_connection("firewall_1", "web_server_1")
    simulator.add_connection("web_server_1", "app_server_1")
    simulator.add_connection("app_server_1", "db_server_1")
    simulator.add_connection("firewall_1", "workstation_1")
    simulator.add_connection("workstation_1", "workstation_2")
    simulator.add_connection("workstation_2", "app_server_1")
    simulator.add_connection("router_1", "firewall_1")

    print(f"   ✓ {len(simulator.network)} nodos añadidos")
    print(f"   ✓ {sum(len(v) for v in simulator.attack_graph.values()) // 2} conexiones establecidas")
    print()

    # Construir STS
    print("[2] Construyendo Sistema de Transición de Estados...")
    simulator.build_sts(max_depth=4)
    print(f"   ✓ {len(simulator.sts.states)} estados generados")
    print(f"   ✓ {len(simulator.sts.attack_actions)} acciones de ataque posibles")
    print(f"   ✓ {sum(len(v) for v in simulator.sts.transitions.values())} transiciones")
    print()

    # Analizar métricas de seguridad
    print("[3] Calculando métricas de seguridad...")
    metrics = simulator.analyze_security_metrics()

    print("\n   MÉTRICAS DE SEGURIDAD:")
    print(f"   • Total de estados en el STS: {metrics['total_states']}")
    print(f"   • Estados con compromiso: {metrics['compromised_states']}")
    print(f"   • Superficie de ataque: {metrics['attack_surface_size']} vectores")
    print(f"   • Profundidad máxima de ataque: {metrics['max_attack_depth']} saltos")
    print(f"   • Probabilidad de compromiso total: {metrics['total_compromise_probability']:.2%}")
    print(f"   • Tiempo mínimo a estado crítico: {metrics['min_time_to_critical_hours']:.1f} horas")
    print()

    # Encontrar camino de ataque óptimo
    print("[4] Analizando caminos de ataque óptimos...")
    optimal_path = simulator.find_optimal_attack_path()

    if optimal_path:
        print(f"\n   CAMINO DE ATAQUE ÓPTIMO ENCONTRADO ({len(optimal_path)} pasos):")
        for i, action in enumerate(optimal_path, 1):
            print(f"   {i}. {action.attack_vector.name}: {action.source_node} → {action.target_node}")
            print(f"      Probabilidad: {action.success_probability:.1%}, "
                  f"Costo: ${action.cost:.0f}, "
                  f"Tiempo: {action.time_required:.1f}h")
    else:
        print("   No se encontró camino de ataque viable")
    print()

    # Simulación Monte Carlo
    print("[5] Ejecutando simulación Monte Carlo (100 iteraciones)...")
    simulation_results = simulator.simulate_attack_scenario(num_simulations=100)

    print("\n   RESULTADOS DE SIMULACIÓN:")
    print(f"   • Tasa de éxito de ataques: {simulation_results['success_rate']:.1%}")
    print(f"   • Tiempo promedio de compromiso: {simulation_results['avg_time_to_compromise']:.1f} horas")
    print(f"   • Nodos promedio comprometidos: {simulation_results['avg_nodes_compromised']:.1f}")

    print("\n   VECTORES DE ATAQUE MÁS EXITOSOS:")
    for attack_type, count in sorted(
        simulation_results['most_successful_attacks'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]:
        print(f"      • {attack_type}: {count} éxitos")

    print("\n   NODOS MÁS ATACADOS:")
    for node, count in sorted(
        simulation_results['most_targeted_nodes'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:5]:
        print(f"      • {node}: {count} ataques")

    print()
    print("=" * 80)
    print("ANÁLISIS COMPLETADO")
    print("=" * 80)

    return simulator, metrics, simulation_results


if __name__ == "__main__":
    simulator, metrics, simulations = demonstrate_model()










































