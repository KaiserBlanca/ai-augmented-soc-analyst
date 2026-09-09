import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

from soc_analyst.parsers.apache import parse_line
from soc_analyst.detection.sqli import SQLInjectionDetector
from soc_analyst.detection.xss import XSSDetector
from soc_analyst.risk.evaluator import RiskEvaluator
from soc_analyst.ai.enricher import GeminiEnricher

env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

DEFAULT_TEST_LOG = '192.168.1.50 - - [09/Sep/2026:02:15:00 +0300] "GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 4523 "-" "Mozilla/5.0"'

def main():
    parser = argparse.ArgumentParser(description="SOC Threat Detection & AI Enrichment CLI")
    parser.add_argument("--log", type=str, nargs="?", const=DEFAULT_TEST_LOG, default=DEFAULT_TEST_LOG, help="Single Apache log line to analyze")
    args = parser.parse_args()

    log_to_analyze = args.log if args.log else DEFAULT_TEST_LOG

    # 1. Parse Log
    event = parse_line(log_to_analyze)
    if not event:
        print("[!] Failed to parse log line.")
        sys.exit(1)

    print(f"\n[+] Parsed Log: {event.method} {event.path} ({event.source_ip})")

    # 2. Run Detectors
    detectors = [SQLInjectionDetector(), XSSDetector()]
    findings = []
    for d in detectors:
        findings.extend(d.detect(event))

    if not findings:
        print("[+] No threats detected.")
        sys.exit(0)

    # 3. Evaluate Risk
    evaluator = RiskEvaluator()
    risk_assessment = evaluator.evaluate(findings[0], event)
    
    attack_type_str = findings[0].attack_type.value if hasattr(findings[0].attack_type, 'value') else findings[0].attack_type
    risk_level_obj = getattr(risk_assessment, 'risk_level', None)
    risk_level_str = risk_level_obj.value if hasattr(risk_level_obj, 'value') else str(risk_level_obj)

    print(f"[!] Threat Detected: {findings[0].rule_id} - {attack_type_str}")
    print(f"[!] Dynamic Risk Score: {risk_assessment.risk_score}/100 ({risk_level_str})")

    # 4. AI Enrichment
    enricher = GeminiEnricher()
    try:
        enrichment = enricher.enrich(findings[0], event, risk_score=risk_assessment.risk_score)
    except TypeError:
        enrichment = enricher.enrich(findings[0], event)

    print("\n" + "="*50)
    print("AI SOC ANALYST ENRICHMENT REPORT")
    print("="*50)
    
    exec_summary = getattr(enrichment, 'executive_summary', None) or getattr(enrichment, 'summary', '')
    root_cause = getattr(enrichment, 'root_cause_analysis', None) or getattr(enrichment, 'root_cause', '')
    playbook = getattr(enrichment, 'remediation_playbook', None) or getattr(enrichment, 'playbook', '')

    print(f"\n[Executive Summary]\n{exec_summary}")
    print(f"\n[Root Cause Analysis]\n{root_cause}")
    print(f"\n[Remediation Playbook]\n{playbook}")

if __name__ == "__main__":
    main()