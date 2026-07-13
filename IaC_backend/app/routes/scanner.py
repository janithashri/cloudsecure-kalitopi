from flask import Blueprint, request, jsonify, send_file
from app.services.github_service import clone_repository
from app.services.scan_service import run_iac_scan
from app.utils.file_manager import safe_cleanup
from app.utils.reporting import export_to_pdf , export_to_csv
from app.services.ai_service import get_ai_remediation
import os

scanner_bp = Blueprint('scanner', __name__)


scan_storage = {}


from app.services.ai_service import get_ai_remediation 

@scanner_bp.route('/api/iac/scan', methods=['POST'])
def start_scan():
    data = request.json
    repo_url = data.get('repoUrl')

    if not repo_url:
        return jsonify({"error": "URL is required"}), 400

    try:
        # 1. Clone the repository
        path, scan_id = clone_repository(repo_url)
        
        # 2. Run the IaC scan
        results_payload = run_iac_scan(path)
        
        # Logic to handle results structure
        if isinstance(results_payload, list):
            findings = results_payload
        elif isinstance(results_payload, dict):
            findings = results_payload.get('results', [])
            if isinstance(findings, dict):
                findings = findings.get('results', [])
        else:
            findings = []

       
        for issue in findings:
            severity = issue.get('severity', '').upper()
            if severity in ['CRITICAL', 'HIGH']:
                issue['ai_fix'] = get_ai_remediation(issue)
        # ---------------------------------
        
       
        scan_storage[scan_id] = findings
        
        
        safe_cleanup(path)
        
        return jsonify({
            "scanId": scan_id,
            "results": findings,
            "message": "Scan completed successfully with AI remediation"
        })
    except Exception as e:
        print(f"Scan Error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@scanner_bp.route('/api/iac/export', methods=['GET'])
def export_scan_results():
    scan_id = request.args.get('scanId')
    format_type = request.args.get('format', 'pdf').lower() 
    
    if not scan_id or scan_id not in scan_storage:
        return jsonify({"error": "Scan results not found or expired"}), 404

    try:
        results = scan_storage[scan_id]
        
       
        if format_type == 'csv':
            file_path = export_to_csv(results, filename=f"report_{scan_id}.csv")
            mimetype = 'text/csv'
            download_name = f"CloudSecure_Audit_{scan_id}.csv"
        else:
            file_path = export_to_pdf(results, filename=f"report_{scan_id}.pdf")
            mimetype = 'application/pdf'
            download_name = f"CloudSecure_Audit_{scan_id}.pdf"

        if not os.path.exists(file_path):
            return jsonify({"error": f"Failed to generate {format_type} file"}), 500

        response = send_file(
            file_path,
            as_attachment=True,
            download_name=download_name,
            mimetype=mimetype
        )

        @response.call_on_close
        def cleanup_temp_file():
            if os.path.exists(file_path):
                os.remove(file_path)
                
        return response
        
    except Exception as e:
        return jsonify({"error": f"Export failed: {str(e)}"}), 500