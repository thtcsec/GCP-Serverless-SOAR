# Sub-Workflows for Enterprise SOAR
# Individual workflows for specific incident response tasks

resource "google_workflows_workflow" "detect_severity" {
  name        = "${var.environment}-soar-detect-severity"
  region      = var.region
  description = "Detects and analyzes security finding severity"

  service_account = google_service_account.workflow_sa.email

  source_contents = file("${path.module}/workflows/detect_severity.yaml")

  labels = merge(
    var.labels,
    {
      workflow = "detect-severity"
    }
  )
}

resource "google_workflows_workflow" "isolate_instance" {
  name        = "${var.environment}-soar-isolate-instance"
  region      = var.region
  description = "Isolates compromised VM instance"

  service_account = google_service_account.workflow_sa.email

  source_contents = file("${path.module}/workflows/isolate_instance.yaml")

  labels = merge(
    var.labels,
    {
      workflow = "isolate-instance"
    }
  )
}

resource "google_workflows_workflow" "create_snapshot" {
  name        = "${var.environment}-soar-create-snapshot"
  region      = var.region
  description = "Creates forensic snapshots of compromised instance"

  service_account = google_service_account.workflow_sa.email

  source_contents = file("${path.module}/workflows/create_snapshot.yaml")

  labels = merge(
    var.labels,
    {
      workflow = "create-snapshot"
    }
  )
}

resource "google_workflows_workflow" "terminate_instance" {
  name        = "${var.environment}-soar-terminate-instance"
  region      = var.region
  description = "Terminates compromised instance after approval"

  service_account = google_service_account.workflow_sa.email

  source_contents = file("${path.module}/workflows/terminate_instance.yaml")

  labels = merge(
    var.labels,
    {
      workflow = "terminate-instance"
    }
  )
}

resource "google_workflows_workflow" "notify_team" {
  name        = "${var.environment}-soar-notify-team"
  region      = var.region
  description = "Notifies security team via multiple channels"

  service_account = google_service_account.workflow_sa.email

  source_contents = file("${path.module}/workflows/notify_team.yaml")

  labels = merge(
    var.labels,
    {
      workflow = "notify-team"
    }
  )
}

resource "google_workflows_workflow" "enrich_threat_intel" {
  name        = "${var.environment}-soar-enrich-threat-intel"
  region      = var.region
  description = "Enriches threat data with external intelligence"

  service_account = google_service_account.workflow_sa.email

  source_contents = <<-EOF
# Enrich Threat Intelligence Workflow
main:
  params: [args]
  steps:
    - fetch_virustotal:
        try:
          call: http.get
          args:
            url: $${"https://www.virustotal.com/api/v3/ip_addresses/" + args.ip_address}
            headers:
              x-apikey: $${var.virustotal_api_key}
          result: vt_response
        except:
          assign:
            - vt_result:
                malicious: false
                score: 0
        assign:
          - vt_result:
              malicious: $${vt_response.body.data.attributes.last_analysis_stats.malicious > 0}
              score: $${vt_response.body.data.attributes.last_analysis_stats.malicious}

    - fetch_abuseipdb:
        try:
          call: http.get
          args:
            url: $${"https://api.abuseipdb.com/api/v2/check?ipAddress=" + args.ip_address}
            headers:
              Key: $${var.abuseipdb_api_key}
              Accept: "application/json"
          result: abuse_response
        except:
          assign:
            - abuse_result:
                isp: "unknown"
                is_whitelisted: false
                abuse_confidence_score: 0
        assign:
          - abuse_result:
              isp: $${abuse_response.body.data.isp}
              is_whitelisted: $${abuse_response.body.data.is_whitelisted}
              abuse_confidence_score: $${abuse_response.body.data.abuseConfidenceScore}

    - calculate_intel_score:
        assign:
          - threat_intel_score: 0
          - threat_intel_details: []

        switch:
          - condition: $${vt_result.malicious == true}
            assign:
              - threat_intel_score: $${threat_intel_score + 50}
              - threat_intel_details: $${threat_intel_details + ["VirusTotal: Malicious"]}

        switch:
          - condition: $${abuse_result.abuse_confidence_score > 50}
            assign:
              - threat_intel_score: $${threat_intel_score + 30}
              - threat_intel_details: $${threat_intel_details + ["AbuseIPDB: High confidence"]}

        switch:
          - condition: $${abuse_result.is_whitelisted == false}
            assign:
              - threat_intel_score: $${threat_intel_score + 10}

    - return_result:
        return:
          ip_address: $${args.ip_address}
          threat_intel_score: $${threat_intel_score}
          virustotal: $${vt_result}
          abuseipdb: $${abuse_result}
          details: $${threat_intel_details}
          timestamp: $${sys.get_env("sys.now")}
EOF

  labels = merge(
    var.labels,
    {
      workflow = "enrich-threat-intel"
    }
  )
}

resource "google_workflows_workflow" "generate_report" {
  name        = "${var.environment}-soar-generate-report"
  region      = var.region
  description = "Generates comprehensive incident response report"

  service_account = google_service_account.workflow_sa.email

  source_contents = <<-EOF
# Generate Incident Report Workflow
main:
  params: [args]
  steps:
    - prepare_report_data:
        assign:
          - report_id: $${"INC-" + sys.get_env("sys.now").replace("-", "").replace(":", "").replace("T", "-")}
          - report_timestamp: $${sys.get_env("sys.now")}

    - create_report_document:
        assign:
          - report_content:
              incident_report:
                report_id: $${report_id}
                timestamp: $${report_timestamp}
                finding:
                  finding_id: $${args.finding_id}
                  severity: $${args.severity}
                  threat_type: $${args.threat_type}
                  category: $${args.category}
                affected_resource:
                  instance_id: $${args.instance_id}
                  instance_name: $${args.instance_name}
                  zone: $${args.zone}
                  project_id: $${args.project_id}
                timeline:
                  detected: $${args.detected_time}
                  isolated: $${args.isolated_time}
                  snapshotted: $${args.snapshotted_time}
                  terminated: $${args.terminated_time}
                actions_taken: $${args.actions_taken}
                risk_assessment:
                  risk_score: $${args.risk_score}
                  threat_intel_score: $${args.threat_intel_score}
                recommendations: $${args.recommendations}
                status: $${args.status}

    - store_report:
        call: http.post
        args:
          url: https://storage.googleapis.com/upload/storage/v1/b/$${var.reports_bucket}/o
          query:
            name: $${"reports/" + report_id + ".json"}
          body: $${report_content}
          headers:
            Content-Type: "application/json"
        result: storage_result

    - create_pdf_report:
        call: http.post
        args:
          url: $${var.report_generator_function}
          body:
            report_id: $${report_id}
            content: $${report_content}
        result: pdf_result

    - log_report_generation:
        call: http.post
        args:
          url: https://logging.googleapis.com/v2/entries:write
          auth:
            type: OAuth2
          body:
            logName: $${"projects/" + sys.get_env("GOOGLE_CLOUD_PROJECT_ID") + "/logs/soar-reports"}
            resource:
              type: global
            entries:
              - severity: INFO
                textPayload: $${"Report generated: " + report_id}

    - return_report:
        return:
          report_id: $${report_id}
          report_url: $${storage_result.body.selfLink}
          pdf_url: $${pdf_result.body.url}
          timestamp: $${report_timestamp}
EOF

  labels = merge(
    var.labels,
    {
      workflow = "generate-report"
    }
  )
}

resource "google_workflows_workflow" "forward_to_siem" {
  name        = "${var.environment}-soar-forward-to-siem"
  region      = var.region
  description = "Forwards security events to SIEM platforms"

  service_account = google_service_account.workflow_sa.email

  source_contents = <<-EOF
# Forward to SIEM Workflow
main:
  params: [args]
  steps:
    - prepare_splunk_event:
        call: http.post
        args:
          url: $${var.splunk_hec_url}
          headers:
            Authorization: $${"Splunk " + var.splunk_hec_token}
            Content-Type: application/json
          body:
            time: $${parseInt(sys.get_env("sys.now"))}
            host: $${args.instance_id}
            source: "gcp-soar"
            sourcetype: "soar:incident"
            event:
              finding_id: $${args.finding_id}
              severity: $${args.severity}
              threat_type: $${args.threat_type}
              action: $${args.action_taken}
              instance_id: $${args.instance_id}
              project_id: $${args.project_id}
              timestamp: $${args.timestamp}
        result: splunk_result
        next: prepare_datadog_event

    - prepare_datadog_event:
        call: http.post
        args:
          url: https://api.datadoghq.com/api/v1/series
          headers:
            DD-API-KEY: $${var.datadog_api_key}
            Content-Type: application/json
          body:
            series:
              - metric: soar.incident
                points:
                  - $${parseInt(sys.get_env("sys.now"))}: 1
                tags:
                  - $${"severity:" + args.severity}
                  - $${"threat_type:" + args.threat_type}
                  - $${"action:" + args.action_taken}
        result: datadog_result
        next: return_status

    - return_status:
        return:
          splunk_status: $${splunk_result.body.code}
          datadog_status: $${datadog_result.body.status}
          forwarded_at: $${sys.get_env("sys.now")}
EOF

  labels = merge(
    var.labels,
    {
      workflow = "forward-to-siem"
    }
  )
}

resource "google_workflows_workflow" "incident_response" {
  name        = "${var.environment}-soar-incident-response"
  region      = var.region
  description = "Main incident response orchestration workflow"

  service_account = google_service_account.workflow_sa.email

  source_contents = <<-EOF
# Main Incident Response Orchestration Workflow
main:
  params: [args]
  steps:
    - log_start:
        call: http.post
        args:
          url: https://logging.googleapis.com/v2/entries:write
          body:
            logName: $${"projects/" + sys.get_env("GOOGLE_CLOUD_PROJECT_ID") + "/logs/soar-incidents"}
            resource:
              type: global
            entries:
              - severity: INFO
                textPayload: $${"Starting incident response for: " + args.finding_id}

    - detect_severity:
        call: googleapis.workflowmanagement.googleapis.com.v1.projects.locations.workflows.executions.create
        args:
          name: $${"projects/" + sys.get_env("GOOGLE_CLOUD_PROJECT_ID") + "/locations/" + var.region + "/workflows/" + google_workflows_workflow.detect_severity.id}
          argument:
            finding_id: $${args.finding_id}
            threat_type: $${args.threat_type}
            source: $${args.source}
        result: severity_result
        next: check_critical

    - check_critical:
        switch:
          - condition: $${severity_result.result.severity == "CRITICAL" or severity_result.result.severity == "HIGH"}
            next: isolate_and_snapshot

        next: enrich_intel

    - isolate_and_snapshot:
        parallel:
          branches:
            - isolate:
                steps:
                  - call_isolate:
                      call: googleapis.workflowmanagement.googleapis.com.v1.projects.locations.workflows.executions.create
                      args:
                        name: $${"projects/" + sys.get_env("GOOGLE_CLOUD_PROJECT_ID") + "/locations/" + var.region + "/workflows/" + google_workflows_workflow.isolate_instance.id}
                        argument:
                          instance_id: $${args.instance_id}
                          zone: $${args.zone}
                          project_id: $${args.project_id}
                      result: isolate_result
            - snapshot:
                steps:
                  - call_snapshot:
                      call: googleapis.workflowmanagement.googleapis.com.v1.projects.locations.workflows.executions.create
                      args:
                        name: $${"projects/" + sys.get_env("GOOGLE_CLOUD_PROJECT_ID") + "/locations/" + var.region + "/workflows/" + google_workflows_workflow.create_snapshot.id}
                        argument:
                          instance_id: $${args.instance_id}
                          zone: $${args.zone}
                          project_id: $${args.project_id}
                      result: snapshot_result

    - enrich_intel:
        call: googleapis.workflowmanagement.googleapis.com.v1.projects.locations.workflows.executions.create
        args:
          name: $${"projects/" + sys.get_env("GOOGLE_CLOUD_PROJECT_ID") + "/locations/" + var.region + "/workflows/" + google_workflows_workflow.enrich_threat_intel.id}
          argument:
            ip_address: $${args.ip_address}
        result: intel_result
        next: notify_team

    - notify_team:
        call: googleapis.workflowmanagement.googleapis.com.v1.projects.locations.workflows.executions.create
        args:
          name: $${"projects/" + sys.get_env("GOOGLE_CLOUD_PROJECT_ID") + "/locations/" + var.region + "/workflows/" + google_workflows_workflow.notify_team.id}
          argument:
            finding_id: $${args.finding_id}
            severity: $${severity_result.result.severity}
            instance_id: $${args.instance_id}
            threat_intel: $${intel_result.result}
        result: notify_result
        next: generate_report

    - generate_report:
        call: googleapis.workflowmanagement.googleapis.com.v1.projects.locations.workflows.executions.create
        args:
          name: $${"projects/" + sys.get_env("GOOGLE_CLOUD_PROJECT_ID") + "/locations/" + var.region + "/workflows/" + google_workflows_workflow.generate_report.id}
          argument:
            finding_id: $${args.finding_id}
            severity: $${severity_result.result.severity}
            threat_type: $${args.threat_type}
            instance_id: $${args.instance_id}
            actions_taken: $${isolate_result.result.action_taken}
            threat_intel_score: $${intel_result.result.threat_intel_score}
        result: report_result
        next: forward_to_siem

    - forward_to_siem:
        call: googleapis.workflowmanagement.googleapis.com.v1.projects.locations.workflows.executions.create
        args:
          name: $${"projects/" + sys.get_env("GOOGLE_CLOUD_PROJECT_ID") + "/locations/" + var.region + "/workflows/" + google_workflows_workflow.forward_to_siem.id}
          argument:
            finding_id: $${args.finding_id}
            severity: $${severity_result.result.severity}
            threat_type: $${args.threat_type}
            action_taken: $${isolate_result.result.action_taken}
            instance_id: $${args.instance_id}
            timestamp: $${sys.get_env("sys.now")}
        result: siem_result
        next: return_response

    - return_response:
        return:
          status: "completed"
          finding_id: $${args.finding_id}
          severity: $${severity_result.result.severity}
          actions_taken:
            isolated: $${isolate_result.result.success}
            snapshotted: $${snapshot_result.result.success}
            notified: $${notify_result.result.success}
          reports:
            report_id: $${report_result.result.report_id}
            report_url: $${report_result.result.report_url}
          threat_intel:
            score: $${intel_result.result.threat_intel_score}
            details: $${intel_result.result.details}
          siem_status: $${siem_result.result}
          completed_at: $${sys.get_env("sys.now")}
EOF

  labels = merge(
    var.labels,
    {
      workflow = "incident-response"
    }
  )
}
