"""
Example Usage - Demonstrating how to use the Multimodal Cybersecurity System components
"""

import json
from config import SystemConfig
from multimodal_processor import MultimodalDataProcessor
from llm_analysis import LLMThreatAnalyzer, ThreatAlertGenerator
from threat_alert import ThreatAlertManager, AlertNotifier, AlertAnalytics
from network_capture import NetworkCapture

def example_1_basic_threat_detection():
    """Example 1: Basic threat detection workflow"""
    print("\n" + "="*80)
    print("EXAMPLE 1: Basic Threat Detection")
    print("="*80)
    
    # Initialize components
    processor = MultimodalDataProcessor(SystemConfig.PROCESSING_CONFIG)
    analyzer = LLMThreatAnalyzer(SystemConfig.LLM_CONFIG)
    
    # Process multimodal data
    print("\n1. Processing multimodal data...")
    data = processor.process_all()
    print(f"   Processed {data['aggregated_data']['total_events']} events")
    
    # Analyze threats
    print("\n2. Analyzing threats with LLM...")
    analysis = analyzer.perform_threat_analysis(data['llm_input'])
    print(f"   Threat Type: {analysis['threat_analysis']['threat_type']}")
    print(f"   Risk Level: {analysis['overall_risk_level']}")
    print(f"   Risk Score: {analysis['overall_risk_score']}")
    
    # Display recommendations
    print("\n3. Recommended Actions:")
    for i, action in enumerate(analysis['recommendations'], 1):
        print(f"   {i}. {action}")

def example_2_network_traffic_analysis():
    """Example 2: Advanced network traffic analysis"""
    print("\n" + "="*80)
    print("EXAMPLE 2: Network Traffic Analysis")
    print("="*80)
    
    # Initialize network capture
    capture = NetworkCapture(SystemConfig.NETWORK_CONFIG)
    
    # Capture packets
    print("\n1. Capturing network packets...")
    packets = capture.capture_packets(packet_count=100)
    print(f"   Captured {len(packets)} packets")
    
    # Analyze flows
    print("\n2. Analyzing traffic flows...")
    flows = capture.analyze_flows()
    print(f"   Identified {len(flows)} unique flows")
    
    # Get traffic summary
    print("\n3. Traffic Summary:")
    summary = capture.get_traffic_summary()
    print(f"   Total Packets: {summary['total_packets']}")
    print(f"   Total Bytes: {summary['total_bytes']}")
    print(f"   Unique Flows: {summary['unique_flows']}")
    print(f"   Average Packet Size: {summary['average_packet_size']:.2f} bytes")
    
    # Detect suspicious patterns
    print("\n4. Detecting suspicious patterns...")
    patterns = capture.detect_suspicious_patterns()
    print(f"   Found {len(patterns)} suspicious patterns")
    for pattern in patterns[:3]:
        print(f"   - {pattern['pattern']}: {pattern['description']}")

def example_3_alert_management():
    """Example 3: Alert management and escalation"""
    print("\n" + "="*80)
    print("EXAMPLE 3: Alert Management")
    print("="*80)
    
    # Initialize components
    processor = MultimodalDataProcessor(SystemConfig.PROCESSING_CONFIG)
    analyzer = LLMThreatAnalyzer(SystemConfig.LLM_CONFIG)
    alert_manager = ThreatAlertManager()
    
    # Create mock analysis result
    print("\n1. Running threat analysis...")
    data = processor.process_all()
    analysis = analyzer.perform_threat_analysis(data['llm_input'])
    
    # Generate alert
    print("\n2. Generating alert...")
    alert_generator = ThreatAlertGenerator()
    alert = alert_generator.generate_alert(analysis)
    print(f"   Alert ID: {alert['alert_id']}")
    print(f"   Threat Type: {alert['threat_type']}")
    print(f"   Risk Level: {alert['risk_level']}")
    
    # Create alert in manager
    print("\n3. Managing alert...")
    alert_manager.create_alert(analysis)
    
    # Acknowledge alert
    print("\n4. Acknowledging alert...")
    alert_manager.acknowledge_alert(alert['alert_id'], notes="Investigating this threat")
    print(f"   Alert acknowledged")
    
    # Escalate alert
    print("\n5. Escalating alert...")
    alert_manager.escalate_alert(alert['alert_id'])
    print(f"   Alert escalated")
    
    # View summary
    print("\n6. Alert Summary:")
    summary = alert_manager.generate_alert_summary()
    print(f"   Total Alerts: {summary['total_alerts']}")
    print(f"   Active Alerts: {summary['active_alerts']}")
    print(f"   Critical Alerts: {summary['critical_alerts']}")

def example_4_multimodal_correlation():
    """Example 4: Advanced multimodal event correlation"""
    print("\n" + "="*80)
    print("EXAMPLE 4: Multimodal Event Correlation")
    print("="*80)
    
    # Initialize processor
    processor = MultimodalDataProcessor(SystemConfig.PROCESSING_CONFIG)
    analyzer = LLMThreatAnalyzer(SystemConfig.LLM_CONFIG)
    
    # Process all data sources
    print("\n1. Processing data from all sources...")
    data = processor.process_all()
    
    # Display correlations
    print("\n2. Event Correlations Found:")
    for i, corr in enumerate(data['correlations'][:5], 1):
        print(f"\n   Correlation {i}:")
        print(f"   - Sources: {', '.join(corr['correlated_sources'])}")
        print(f"   - IP: {corr['ip']}")
        print(f"   - Event Count: {corr['event_count']}")
        print(f"   - Confidence: {corr['confidence']:.2f}")
    
    # Perform multimodal correlation analysis
    print("\n3. Performing multimodal correlation analysis...")
    events = list(data['aggregated_data'].values())[:5]
    correlation_result = analyzer.correlate_multimodal_events(events)
    print(f"   Correlation Pattern: {correlation_result['pattern']}")
    print(f"   Risk Level: {correlation_result['risk_level']}")

def example_5_knowledge_base_reasoning():
    """Example 5: Retrieval-augmented reasoning with knowledge base"""
    print("\n" + "="*80)
    print("EXAMPLE 5: Knowledge Base Reasoning")
    print("="*80)
    
    analyzer = LLMThreatAnalyzer(SystemConfig.LLM_CONFIG)
    
    # Example threat indicators
    threat_type = "data_exfiltration"
    indicators = ["large_transfer", "unusual_ip", "admin_access", "suspicious_dns"]
    
    print(f"\n1. Threat Type: {threat_type}")
    print(f"2. Indicators: {', '.join(indicators)}")
    
    # Perform retrieval-augmented reasoning
    print("\n3. Searching knowledge base...")
    rar_result = analyzer.retrieval_augmented_reasoning(threat_type, indicators)
    
    # Display results
    print(f"\n4. Knowledge Base Matches: {len(rar_result['matching_knowledge'])}")
    for match in rar_result['matching_knowledge']:
        print(f"   - Threat: {match['threat']}")
        print(f"   - Indicator: {match['indicator']}")
        print(f"   - Remediation: {match['remediation']}")
    
    # Display enriched analysis
    if rar_result['enriched_analysis']:
        print(f"\n5. Enriched Analysis:")
        print(f"   - Severity: {rar_result['enriched_analysis'].get('severity', 'N/A')}")
        print(f"   - Indicators: {rar_result['enriched_analysis'].get('indicators', [])}")
        print(f"   - Remediation: {rar_result['enriched_analysis'].get('remediation', 'N/A')}")

def example_6_alert_notifications():
    """Example 6: Alert notification system"""
    print("\n" + "="*80)
    print("EXAMPLE 6: Alert Notifications")
    print("="*80)
    
    # Initialize components
    processor = MultimodalDataProcessor(SystemConfig.PROCESSING_CONFIG)
    analyzer = LLMThreatAnalyzer(SystemConfig.LLM_CONFIG)
    notifier = AlertNotifier(SystemConfig.ALERT_CONFIG)
    
    # Create threat alert
    print("\n1. Creating threat alert...")
    data = processor.process_all()
    analysis = analyzer.perform_threat_analysis(data['llm_input'])
    
    alert_generator = ThreatAlertGenerator()
    alert = alert_generator.generate_alert(analysis)
    print(f"   ✓ Alert created: {alert['alert_id']}")
    
    # Broadcast alert
    print("\n2. Broadcasting alert through channels...")
    results = notifier.broadcast_alert(alert)
    
    print("\n3. Notification Results:")
    for channel, success in results.items():
        status = "✓" if success else "✗"
        print(f"   {status} {channel.upper()}: {'Sent' if success else 'Skipped'}")
    
    # View formatted messages
    print("\n4. Alert Message Formats:")
    
    # Email format
    email_msg = notifier._format_alert_email(alert)
    print("\n   Email Format (first 3 lines):")
    for line in email_msg.split('\n')[:3]:
        print(f"   {line}")
    
    # Slack format
    slack_msg = notifier._format_slack_message(alert)
    print("\n   Slack Format:")
    print(f"   Title: {slack_msg['attachments'][0]['title']}")
    print(f"   Color: {slack_msg['attachments'][0]['color']}")

def example_7_analytics_reporting():
    """Example 7: Analytics and reporting"""
    print("\n" + "="*80)
    print("EXAMPLE 7: Analytics & Reporting")
    print("="*80)
    
    # Generate multiple alerts
    processor = MultimodalDataProcessor(SystemConfig.PROCESSING_CONFIG)
    analyzer = LLMThreatAnalyzer(SystemConfig.LLM_CONFIG)
    alert_manager = ThreatAlertManager()
    
    print("\n1. Generating multiple threat alerts...")
    for i in range(3):
        data = processor.process_all()
        analysis = analyzer.perform_threat_analysis(data['llm_input'])
        alert_manager.create_alert(analysis)
        print(f"   Alert {i+1} created")
    
    # Perform analytics
    print("\n2. Performing analytics...")
    analytics = AlertAnalytics(alert_manager.alerts)
    stats = analytics.get_alert_statistics()
    
    print("\n3. Alert Statistics:")
    print(f"   Total Alerts: {stats['total_alerts']}")
    print(f"   Average Risk Score: {stats['average_risk_score']:.2f}")
    print(f"\n   Alerts by Risk Level:")
    for level, count in stats['alerts_by_risk_level'].items():
        print(f"   - {level}: {count}")
    print(f"\n   Alerts by Threat Type:")
    for threat, count in list(stats['alerts_by_threat_type'].items())[:5]:
        print(f"   - {threat}: {count}")
    
    # Generate report
    print("\n4. Generating report...")
    report = analytics.generate_report()
    print(report)

def main():
    """Run all examples"""
    print("\n" + "="*80)
    print("MULTIMODAL CYBERSECURITY SYSTEM - USAGE EXAMPLES")
    print("="*80)
    
    examples = [
        ("Basic Threat Detection", example_1_basic_threat_detection),
        ("Network Traffic Analysis", example_2_network_traffic_analysis),
        ("Alert Management", example_3_alert_management),
        ("Multimodal Correlation", example_4_multimodal_correlation),
        ("Knowledge Base Reasoning", example_5_knowledge_base_reasoning),
        ("Alert Notifications", example_6_alert_notifications),
        ("Analytics & Reporting", example_7_analytics_reporting),
    ]
    
    num_examples = len(examples)
    
    while True:
        print("\n" + "="*80)
        print("SELECT EXAMPLE TO RUN")
        print("="*80 + "\n")
        
        for i, (name, _) in enumerate(examples, 1):
            print(f"{i}. {name}")
        print(f"{num_examples + 1}. Run All Examples")
        print(f"{num_examples + 2}. Exit")
        
        try:
            choice = int(input(f"\nEnter choice (1-{num_examples + 2}): "))
            
            if 1 <= choice <= num_examples:
                examples[choice - 1][1]()
            elif choice == num_examples + 1:
                for name, example_func in examples:
                    try:
                        example_func()
                    except Exception as e:
                        print(f"\n❌ Error in {name}: {str(e)}")
            elif choice == num_examples + 2:
                print("\n👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please try again.")
            
            input("\nPress Enter to continue...")
        
        except ValueError:
            print("❌ Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {str(e)}")

if __name__ == "__main__":
    main()
