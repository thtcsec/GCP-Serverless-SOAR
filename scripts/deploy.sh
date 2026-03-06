#!/bin/bash

# SOAR Platform Deployment Script
# This script deploys the complete SOAR platform for GCP

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$PROJECT_ROOT/terraform"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check gcloud CLI
    if ! command -v gcloud &> /dev/null; then
        log_error "Google Cloud SDK (gcloud) is not installed"
        exit 1
    fi
    
    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check GCP authentication
    if ! gcloud auth print-access-token &> /dev/null; then
        log_error "GCP credentials are not configured or expired. Run 'gcloud auth login'"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Function to initialize Terraform backend
init_terraform_backend() {
    local environment=$1
    log_info "Initializing Terraform backend for $environment environment..."
    
    cd "$TERRAFORM_DIR/environments/$environment"
    
    # Get current GCP project ID
    local project_id=$(gcloud config get-value project)
    local bucket_name="soar-tf-state-$project_id-$environment"
    local region="us-central1"
    
    if ! gsutil ls "gs://$bucket_name" &> /dev/null; then
        log_info "Creating GCS bucket for Terraform state: $bucket_name"
        gsutil mb -p "$project_id" -l "$region" "gs://$bucket_name"
        
        # Enable versioning
        gsutil versioning set on "gs://$bucket_name"
    fi
    
    terraform init
    
    log_success "Terraform backend initialized for $environment"
}

# Function to build and push containers
build_containers() {
    local environment=$1
    log_info "Building containers for $environment environment..."
    
    # Get GCP project ID and region
    local project_id=$(gcloud config get-value project)
    local region="us-central1"
    local registry="${region}-docker.pkg.dev/$project_id/soar-containers"
    
    # Ensure Artifact Registry exists
    if ! gcloud artifacts repositories describe soar-containers --location="$region" &> /dev/null; then
        log_info "Creating Artifact Registry repository: soar-containers"
        gcloud artifacts repositories create soar-containers \
            --repository-format=docker \
            --location="$region" \
            --description="Docker repository for SOAR containers"
    fi
    
    # Configure docker authentication
    gcloud auth configure-docker "${region}-docker.pkg.dev" --quiet
    
    # Build isolation worker
    log_info "Building isolation worker container..."
    cd "$PROJECT_ROOT/containers/isolation-worker"
    docker build -t "soar-isolation-worker:latest" .
    docker tag "soar-isolation-worker:latest" "$registry/soar-isolation-worker:latest"
    docker push "$registry/soar-isolation-worker:latest"
    
    log_success "Containers built and pushed successfully"
}

# Function to deploy infrastructure
deploy_infrastructure() {
    local environment=$1
    log_info "Deploying infrastructure for $environment environment..."
    
    cd "$TERRAFORM_DIR/environments/$environment"
    
    # Plan and apply
    terraform plan -out="terraform.plan"
    terraform apply "terraform.plan"
    
    # Clean up plan file
    rm -f "terraform.plan"
    
    log_success "Infrastructure deployed for $environment"
}

# Function to configure integrations
configure_integrations() {
    local environment=$1
    log_info "Configuring integrations for $environment environment..."
    
    # Slack integration
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        log_info "Configuring Slack integration..."
        gcloud secrets create slack-webhook-url --replication-policy automatic || true
        echo "$SLACK_WEBHOOK_URL" | gcloud secrets versions add slack-webhook-url --data-file=-
    fi
    
    # Jira integration
    if [[ -n "$JIRA_URL" && -n "$JIRA_USERNAME" && -n "$JIRA_API_TOKEN" ]]; then
        log_info "Configuring Jira integration..."
        gcloud secrets create jira-url --replication-policy automatic || true
        echo "$JIRA_URL" | gcloud secrets versions add jira-url --data-file=-
        
        gcloud secrets create jira-username --replication-policy automatic || true
        echo "$JIRA_USERNAME" | gcloud secrets versions add jira-username --data-file=-
        
        gcloud secrets create jira-api-token --replication-policy automatic || true
        echo "$JIRA_API_TOKEN" | gcloud secrets versions add jira-api-token --data-file=-
    fi
    
    # SIEM integration
    if [[ -n "$SIEM_ENDPOINT" && -n "$SIEM_API_KEY" ]]; then
        log_info "Configuring SIEM integration..."
        gcloud secrets create siem-endpoint --replication-policy automatic || true
        echo "$SIEM_ENDPOINT" | gcloud secrets versions add siem-endpoint --data-file=-
        
        gcloud secrets create siem-api-key --replication-policy automatic || true
        echo "$SIEM_API_KEY" | gcloud secrets versions add siem-api-key --data-file=-
    fi
    
    log_success "Integrations configured for $environment"
}

# Function to show deployment summary
show_summary() {
    local environment=$1
    log_info "Deployment summary for $environment environment:"
    
    cd "$TERRAFORM_DIR/environments/$environment"
    
    echo "=== Infrastructure Outputs ==="
    terraform output || log_warning "No outputs found"
    
    echo ""
    echo "=== Next Steps ==="
    echo "1. Configure your integrations using GCP Secret Manager if you haven't yet"
    echo "2. Test the workflow by triggering a Security Command Center finding"
    echo "3. Monitor the execution in Cloud Workflows console"
    echo "4. Check notifications in your configured channels"
    
    echo ""
    echo "=== Useful Commands ==="
    echo "# View Cloud Workflows:"
    echo "gcloud workflows list"
    echo ""
    echo "# View Pub/Sub topics:"
    echo "gcloud pubsub topics list"
    echo ""
    echo "# View Cloud Run services:"
    echo "gcloud run services list"
}

# Function to cleanup
cleanup() {
    local environment=$1
    log_warning "Cleaning up $environment environment..."
    
    cd "$TERRAFORM_DIR/environments/$environment"
    
    # Destroy infrastructure
    terraform destroy -auto-approve
    
    log_success "Cleanup completed for $environment"
}

# Main deployment function
main() {
    local environment=${1:-"dev"}
    local action=${2:-"deploy"}
    
    log_info "SOAR Platform Deployment"
    log_info "Environment: $environment"
    log_info "Action: $action"
    
    case $action in
        "deploy")
            check_prerequisites
            init_terraform_backend "$environment"
            build_containers "$environment"
            deploy_infrastructure "$environment"
            configure_integrations "$environment"
            show_summary "$environment"
            ;;
        "cleanup")
            cleanup "$environment"
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [environment] [action]"
            echo ""
            echo "Environments:"
            echo "  dev         Development environment (default)"
            echo "  staging     Staging environment"
            echo "  prod        Production environment"
            echo ""
            echo "Actions:"
            echo "  deploy      Deploy the platform (default)"
            echo "  cleanup     Destroy all resources"
            echo "  help        Show this help message"
            echo ""
            echo "Environment Variables applicable during deploy:"
            echo "  SLACK_WEBHOOK_URL    Slack webhook URL"
            echo "  JIRA_URL             Jira instance URL"
            echo "  JIRA_USERNAME        Jira API username"
            echo "  JIRA_API_TOKEN       Jira API token"
            echo "  SIEM_ENDPOINT        SIEM API endpoint"
            echo "  SIEM_API_KEY         SIEM API key"
            ;;
        *)
            log_error "Unknown action: $action"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
