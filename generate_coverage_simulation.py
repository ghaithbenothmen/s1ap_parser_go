#!/usr/bin/env python3
"""
Générateur de données de simulation pour tester l'analyse de couverture radio.
Basé sur les données réelles du fichier Parquet existant, mais focalisé sur les failures.
"""

import json
import random
import time
from datetime import datetime, timedelta

def extract_real_patterns(parquet_file):
    """Extrait les patterns réels depuis le fichier Parquet existant"""
    patterns = {
        'source_ips': set(),
        'mme_ids': [],
        'enb_ids': [],
        'cell_patterns': []
    }
    
    try:
        with open(parquet_file, 'r') as f:
            for line_num, line in enumerate(f):
                if line_num >= 100:  # Limite pour l'analyse
                    break
                try:
                    data = json.loads(line.strip())
                    patterns['source_ips'].add(data.get('src_ip', ''))
                    patterns['mme_ids'].append(data.get('mme_ue_s1ap_id', 0))
                    patterns['enb_ids'].append(data.get('enb_ue_s1ap_id', 0))
                except:
                    continue
    except FileNotFoundError:
        print("Fichier Parquet non trouvé, utilisation de valeurs par défaut")
    
    return patterns

def generate_ecgi():
    """Génère un ECGI réaliste basé sur les patterns télécom tunisiens"""
    # PLMN codes pour la Tunisie: 605-01 (Tunisie Telecom), 605-02 (Ooredoo), 605-03 (Orange)
    plmn_codes = ["60501", "60502", "60503"]
    plmn = random.choice(plmn_codes)
    
    # Cell ID: 28 bits (7 digits hex = 28 bits)
    cell_id = f"{random.randint(0x1000000, 0xFFFFFFF):07x}"
    
    return f"{plmn}-{cell_id}", plmn, cell_id

def generate_failure_message(patterns, packet_num, timestamp):
    """Génère un message de failure réaliste"""
    
    # Types de failures avec leurs causes radio typiques
    failure_types = {
        "InitialContextSetupFailure": [
            {"cause": "radio-connection-with-ue-lost", "code": 21, "risk": 10.0},
            {"cause": "failure-in-radio-interface-procedure", "code": 26, "risk": 8.0},
            {"cause": "radio-resources-not-available", "code": 25, "risk": 6.5}
        ],
        "HandoverFailure": [
            {"cause": "handover-failure-in-target-e-utran", "code": 10, "risk": 9.0},
            {"cause": "partial-handover", "code": 5, "risk": 7.0},
            {"cause": "handover-desirable-for-radio-reason", "code": 16, "risk": 5.0}
        ],
        "HandoverPreparationFailure": [
            {"cause": "no-radio-resources-available-in-target-cell", "code": 17, "risk": 6.0},
            {"cause": "handover-failure-in-target-e-utran", "code": 10, "risk": 9.0}
        ],
        "UEContextReleaseRequest": [
            {"cause": "radio-connection-with-ue-lost", "code": 21, "risk": 10.0},
            {"cause": "user-inactivity", "code": 20, "risk": 3.0},
            {"cause": "failure-in-radio-interface-procedure", "code": 26, "risk": 8.0}
        ],
        "E-RABReleaseIndication": [
            {"cause": "radio-connection-with-ue-lost", "code": 21, "risk": 10.0},
            {"cause": "failure-in-radio-interface-procedure", "code": 26, "risk": 8.0}
        ]
    }
    
    # Sélectionner un type de failure
    procedure_name = random.choice(list(failure_types.keys()))
    cause_info = random.choice(failure_types[procedure_name])
    
    # Générer les identifiants
    mme_id = random.choice(patterns['mme_ids']) if patterns['mme_ids'] else random.randint(1000000, 999999999)
    enb_id = random.choice(patterns['enb_ids']) if patterns['enb_ids'] else random.randint(1000, 9999999)
    src_ip = random.choice(list(patterns['source_ips'])) if patterns['source_ips'] else f"10.73.{random.randint(80,210)}.{random.randint(1,254)}"
    dst_ip = "10.3.3.112"  # IP du MME selon les données existantes
    
    # Générer ECGI
    ecgi, plmn, cell_id = generate_ecgi()
    
    # Créer le message
    message = {
        "packet_number": packet_num,
        "timestamp": timestamp.isoformat() + "Z",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "pdu_type": "unsuccessfulOutcome" if "Failure" in procedure_name else "initiatingMessage",
        "pdu_type_code": 2 if "Failure" in procedure_name else 0,
        "procedure_name": procedure_name,
        "procedure_code": {
            "InitialContextSetupFailure": 9,
            "HandoverFailure": 1,
            "HandoverPreparationFailure": 0,
            "UEContextReleaseRequest": 18,
            "E-RABReleaseIndication": 19
        }.get(procedure_name, 99),
        "criticality": "reject",
        "information_elements": [
            {
                "id": 0,
                "name": "id_MME_UE_S1AP_ID",
                "criticality": "reject",
                "value": mme_id,
                "raw_value": str(mme_id)
            },
            {
                "id": 8,
                "name": "id_eNB_UE_S1AP_ID", 
                "criticality": "reject",
                "value": enb_id,
                "raw_value": str(enb_id)
            },
            {
                "id": 2,
                "name": "id_Cause",
                "criticality": "ignore",
                "value": f"radioNetwork: {cause_info['cause']} ({cause_info['code']})",
                "raw_value": f"radioNetwork({cause_info['code']})"
            },
            {
                "id": 100,
                "name": "id_EUTRAN_CGI",
                "criticality": "reject", 
                "value": f"EUTRAN_CGI(PLMN:{plmn}, CellID:{cell_id})",
                "raw_value": ecgi
            }
        ]
    }
    
    return message, cause_info

def generate_coverage_simulation(num_events=50, output_file="coverage_simulation.json"):
    """Génère un fichier de simulation pour l'analyse de couverture"""
    
    print("🔄 Extraction des patterns depuis les données réelles...")
    patterns = extract_real_patterns("parquet:/home/ghaith/coreswitch/sessions2.parquet.as.json")
    
    print(f"📊 Patterns extraits:")
    print(f"   - {len(patterns['source_ips'])} adresses IP sources")
    print(f"   - {len(patterns['mme_ids'])} MME UE S1AP IDs")
    print(f"   - {len(patterns['enb_ids'])} eNB UE S1AP IDs")
    
    events = []
    start_time = datetime.now() - timedelta(hours=1)
    
    print(f"🎯 Génération de {num_events} événements de failure...")
    
    coverage_stats = {
        "InitialContextSetupFailure": 0,
        "HandoverFailure": 0, 
        "HandoverPreparationFailure": 0,
        "UEContextReleaseRequest": 0,
        "E-RABReleaseIndication": 0
    }
    
    risk_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for i in range(num_events):
        timestamp = start_time + timedelta(milliseconds=i*random.randint(10, 1000))
        message, cause_info = generate_failure_message(patterns, i+1, timestamp)
        
        # Statistiques
        coverage_stats[message["procedure_name"]] += 1
        
        if cause_info["risk"] >= 9.0:
            risk_distribution["CRITICAL"] += 1
        elif cause_info["risk"] >= 7.0:
            risk_distribution["HIGH"] += 1
        elif cause_info["risk"] >= 5.0:
            risk_distribution["MEDIUM"] += 1
        else:
            risk_distribution["LOW"] += 1
            
        events.append({
            "message": message,
            "coverage_metadata": {
                "risk_score": cause_info["risk"],
                "severity": "CRITICAL" if cause_info["risk"] >= 9.0 else 
                          "HIGH" if cause_info["risk"] >= 7.0 else
                          "MEDIUM" if cause_info["risk"] >= 5.0 else "LOW",
                "cause_detail": cause_info["cause"],
                "cause_code": cause_info["code"]
            }
        })
    
    # Sauvegarder le fichier
    with open(output_file, 'w') as f:
        json.dump({
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_events": num_events,
                "event_distribution": coverage_stats,
                "risk_distribution": risk_distribution,
                "description": "Simulation focalisée sur les cas de failure pour test de coverage analysis"
            },
            "events": events
        }, f, indent=2)
    
    print(f"✅ Fichier de simulation créé: {output_file}")
    print(f"📈 Distribution des événements:")
    for proc, count in coverage_stats.items():
        if count > 0:
            print(f"   - {proc}: {count} événements")
    
    print(f"🎯 Distribution des risques:")
    for risk, count in risk_distribution.items():
        print(f"   - {risk}: {count} événements")
    
    return output_file

def create_test_pcap_data(simulation_file):
    """Crée des données de test au format attendu par l'analyseur S1AP"""
    
    with open(simulation_file, 'r') as f:
        data = json.load(f)
    
    # Créer un fichier au format simple pour tester
    test_data = []
    for event in data["events"]:
        test_data.append({
            "packet_number": event["message"]["packet_number"],
            "timestamp": event["message"]["timestamp"], 
            "procedure_name": event["message"]["procedure_name"],
            "src_ip": event["message"]["src_ip"],
            "dst_ip": event["message"]["dst_ip"],
            "information_elements": event["message"]["information_elements"],
            "expected_coverage": {
                "should_detect": True,
                "risk_score": event["coverage_metadata"]["risk_score"],
                "severity": event["coverage_metadata"]["severity"]
            }
        })
    
    test_file = "test_coverage_data.json"
    with open(test_file, 'w') as f:
        json.dump(test_data, f, indent=2)
    
    print(f"📋 Fichier de test créé: {test_file}")
    return test_file

if __name__ == "__main__":
    print("🚀 Générateur de simulation pour Coverage Analysis")
    print("=" * 50)
    
    # Générer la simulation
    simulation_file = generate_coverage_simulation(
        num_events=30,
        output_file="/home/ghaith/coreswitch/coverage_simulation.json"
    )
    
    # Créer les données de test
    test_file = create_test_pcap_data(simulation_file)
    
    print("\n✨ Simulation prête!")
    print(f"📁 Fichiers générés:")
    print(f"   - Simulation complète: {simulation_file}")
    print(f"   - Données de test: {test_file}")
    print("\n🔧 Vous pouvez maintenant tester avec:")
    print("   ./build/s1ap-analyzer -coverage-analysis -debug test_coverage_data.json")
