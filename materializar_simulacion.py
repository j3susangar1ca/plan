#!/usr/bin/env python3
import os
import json
import logging
from materializalo import CyberAttackSimulator, NodeType, PrivilegeLevel, AttackVector

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def map_node_type(roles):
    """Mapea los roles de la infraestructura a NodeType del modelo"""
    roles_str = " ".join(roles).lower()
    if "firewall" in roles_str:
        return NodeType.FIREWALL
    if "database" in roles_str or "db" in roles_str:
        return NodeType.DATABASE
    if "workstation" in roles_str:
        return NodeType.WORKSTATION
    if "router" in roles_str or "switch" in roles_str:
        return NodeType.ROUTER
    # Por defecto es SERVER si no encaja en otros
    return NodeType.SERVER

def load_infrastructure(simulator, base_path):
    """Carga nodos y conexiones desde la estructura de directorios"""
    zones_path = os.path.join(base_path, "infrastructure", "zones")
    if not os.path.exists(zones_path):
        logger.error(f"Ruta de zonas no encontrada: {zones_path}")
        return False

    all_hosts = []
    
    # 1. Cargar Nodos
    for zone in os.listdir(zones_path):
        zone_dir = os.path.join(zones_path, zone)
        if not os.path.isdir(zone_dir):
            continue
            
        networks_path = os.path.join(zone_dir, "networks")
        if not os.path.exists(networks_path):
            continue
            
        for network in os.listdir(networks_path):
            net_dir = os.path.join(networks_path, network)
            hosts_path = os.path.join(net_dir, "hosts")
            if not os.path.exists(hosts_path):
                continue
                
            for host_file in os.listdir(hosts_path):
                if not host_file.endswith(".json"):
                    continue
                    
                with open(os.path.join(hosts_path, host_file), 'r') as f:
                    try:
                        data = json.load(f)
                        ip = data.get("ip_address")
                        roles = data.get("roles", [])
                        tech_stack = data.get("tech_stack", [])
                        
                        # Extraer vulnerabilidades de tech_stack y otros campos
                        vulns = []
                        for item in tech_stack:
                            if item.get("status") in ["EOL", "Vulnerable"]:
                                # Intentar inferir vulnerabilidades si no están explícitas
                                # (Para este simplificado, usamos el componente como marca de vulnerabilidad)
                                vulns.append(f"VULN_{item.get('component').upper()}")
                        
                        # Añadir CVEs si existen (algunos archivos pueden tenerlos)
                        if "exploitation_vectors" in data:
                            # Podemos añadir marcas genéricas basadas en riesgo
                            risk = data["exploitation_vectors"].get("risk_level", "BAJO")
                            if risk == "ALTO" or risk == "CRITICO":
                                vulns.append("CRITICAL_VULNERABILITY")

                        node_type = map_node_type(roles)
                        simulator.add_node(ip, node_type, vulnerabilities=vulns)
                        all_hosts.append({"ip": ip, "zone": zone})
                        logger.info(f"Nodo cargado: {ip} ({node_type.name}) en {zone}")
                    except Exception as e:
                        logger.error(f"Error cargando {host_file}: {e}")

    # 2. Establecer Conexiones (Lógica de Segmentación de Red)
    # Reglas simplificadas de conectividad basadas en la arquitectura HCG
    
    # EXTERNAL -> Z01-DMZ
    for host in all_hosts:
        if host["zone"] == "Z01-DMZ":
            simulator.add_connection("EXTERNAL", host["ip"], bidirectional=False)
            
    # Conexiones internas (Full mesh dentro de zonas para simular movimiento lateral libre)
    for i, host_a in enumerate(all_hosts):
        for host_b in all_hosts[i+1:]:
            if host_a["zone"] == host_b["zone"]:
                simulator.add_connection(host_a["ip"], host_b["ip"])
            
            # Z01-DMZ -> Z02-Internal-Servers (Conexión de aplicación)
            if host_a["zone"] == "Z01-DMZ" and host_b["zone"] == "Z02-Internal-Servers":
                simulator.add_connection(host_a["ip"], host_b["ip"], bidirectional=True)
                
            # Z03-Internal-Workstations -> Z02-Internal-Servers (Gestión/Uso)
            if host_a["zone"] == "Z03-Internal-Workstations" and host_b["zone"] == "Z02-Internal-Servers":
                simulator.add_connection(host_a["ip"], host_b["ip"], bidirectional=True)

    return True

def run_materialized_simulation():
    print("=" * 80)
    print("MATERIALIZACIÓN DEL MODELO DE ATAQUE - HOSPITAL CIVIL DE GUADALAJARA")
    print("=" * 80)
    
    simulator = CyberAttackSimulator()
    base_path = "/home/jesuslangarica/plan"
    
    if not load_infrastructure(simulator, base_path):
        print("Error: No se pudo cargar la infraestructura.")
        return

    print(f"\n[1] Infraestructura materializada con {len(simulator.network)} nodos.")
    
    print("[2] Construyendo Sistema de Transición de Estados (STS)...")
    simulator.build_sts(max_depth=3) # Limitamos profundidad por rendimiento en demo
    
    print(f"   ✓ {len(simulator.sts.states)} estados generados.")
    print(f"   ✓ {len(simulator.sts.attack_actions)} vectores de ataque detectados.")
    
    print("\n[3] Análisis de Métricas de Seguridad:")
    metrics = simulator.analyze_security_metrics()
    
    print(f"   • Probabilidad de compromiso total de red: {metrics['total_compromise_probability']:.2%}")
    print(f"   • Tiempo estimado para compromiso crítico: {metrics['min_time_to_critical_hours']:.1f} horas")
    print(f"   • Superficie de ataque: {metrics['attack_surface_size']} vectores únicos")
    
    print("\n[4] Camino de Ataque Óptimo Detectado:")
    optimal_path = simulator.find_optimal_attack_path()
    
    if optimal_path:
        for i, action in enumerate(optimal_path, 1):
            source = action.source_node if action.source_node != "EXTERNAL" else "INTERNET"
            print(f"   {i}. [{action.attack_vector.name}] {source} -> {action.target_node}")
    else:
        print("   No se detectó un camino crítico directo en la profundidad analizada.")

    print("\n[5] Simulación Monte Carlo (Resultados agregados):")
    sim_stats = simulator.simulate_attack_scenario(num_simulations=50)
    print(f"   • Tasa de éxito de intrusión: {sim_stats['success_rate']:.1%}")
    print(f"   • Nodos promedio comprometidos: {sim_stats['avg_nodes_compromised']:.1f}")
    
    print("\n" + "=" * 80)
    print("ANÁLISIS DE MATERIALIZACIÓN COMPLETADO")
    print("=" * 80)

if __name__ == "__main__":
    run_materialized_simulation()
