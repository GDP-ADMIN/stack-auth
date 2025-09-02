#!/bin/bash
# Run './decrypt.sh' and the script will handle everything automatically.

# Decrypt all .enc files according to their environment key
# This script follows the same pattern as the Cloud Build configuration

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to get environment key (first 4 characters)
get_env_key() {
    local environment=$1
    echo "${environment:0:4}"
}

# Function to decrypt a single file
decrypt_file() {
    local filepath=$1
    local environment=$2
    local project=${3:-"gen-ai-template"}

    local env_key
    env_key=$(get_env_key "$environment")
    local plaintext_file="${filepath::-4}"  # Remove .enc extension

    print_status "Decrypting: $filepath"
    print_status "Environment: $environment (key: $env_key)"
    print_status "Output: $plaintext_file"

    if gcloud kms decrypt \
        --ciphertext-file="$filepath" \
        --plaintext-file="$plaintext_file" \
        --location=global \
        --keyring=cloudbuild \
        --key="${project}-${env_key}"; then
        print_success "Successfully decrypted: $filepath"
    else
        print_error "Failed to decrypt: $filepath"
        return 1
    fi
}

# Function to decrypt all files in a directory
decrypt_directory() {
    local dir_path=$1
    local environment=$2
    local project=${3:-"gen-ai-template"}

    if [ ! -d "$dir_path" ]; then
        print_warning "Directory does not exist: $dir_path"
        return 0
    fi

    print_status "Scanning directory: $dir_path"

    # Find all .enc files in the directory and subdirectories
    local enc_files
    enc_files=$(find "$dir_path" -type f -name '*.enc')

    if [ -z "$enc_files" ]; then
        print_status "No .enc files found in: $dir_path"
        return 0
    fi

    local success_count=0
    local total_count=0

    while IFS= read -r -d '' filepath; do
        total_count=$((total_count + 1))
        if decrypt_file "$filepath" "$environment" "$project"; then
            success_count=$((success_count + 1))
        fi
    done < <(find "$dir_path" -type f -name '*.enc' -print0)

    print_status "Decryption summary for $dir_path: $success_count/$total_count files decrypted successfully"

    if [ $success_count -ne $total_count ]; then
        return 1
    fi
}

# Main function
main() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local base_dir="$script_dir"
    local project=${PROJECT:-"gen-ai-template"}

    print_status "Starting decryption process..."
    print_status "Base directory: $base_dir"
    print_status "Project: $project"

    # Check if gcloud is available
    if ! command -v gcloud &> /dev/null; then
        print_error "gcloud CLI is not installed or not in PATH"
        exit 1
    fi

    # Check if user is authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        print_error "Not authenticated with gcloud. Please run 'gcloud auth login'"
        exit 1
    fi

    # Get list of environment directories
    local env_dirs=()
    for dir in "$base_dir"/*/; do
        if [ -d "$dir" ]; then
            local dirname
            dirname=$(basename "$dir")
            env_dirs+=("$dirname")
        fi
    done

    if [ ${#env_dirs[@]} -eq 0 ]; then
        print_error "No environment directories found"
        exit 1
    fi

    print_status "Found environment directories: ${env_dirs[*]}"

    local overall_success=true

    # Process each environment directory
    for env_dir in "${env_dirs[@]}"; do
        print_status "Processing environment: $env_dir"

        if ! decrypt_directory "$base_dir/$env_dir" "$env_dir" "$project"; then
            print_error "Failed to decrypt some files in environment: $env_dir"
            overall_success=false
        fi
    done

    if [ "$overall_success" = true ]; then
        print_success "All files decrypted successfully!"
        exit 0
    else
        print_error "Some files failed to decrypt. Please check the errors above."
        exit 1
    fi
}

# Handle command line arguments
if [ $# -gt 0 ]; then
    case "$1" in
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Decrypt all .enc files in environment directories using Google Cloud KMS"
            echo ""
            echo "Options:"
            echo "  -h, --help     Show this help message"
            echo "  -e, --env      Decrypt specific environment only"
            echo "  -p, --project  Specify project name (default: gen-ai-template)"
            echo ""
            echo "Environment variables:"
            echo "  PROJECT        Project name for KMS key (default: gen-ai-template)"
            echo ""
            echo "Examples:"
            echo "  $0                           # Decrypt all environments"
            echo "  $0 -e dev                    # Decrypt only dev environment"
            echo "  PROJECT=my-project $0        # Use custom project name"
            exit 0
            ;;
        -e|--env)
            if [ -z "${2:-}" ]; then
                print_error "Environment name is required"
                exit 1
            fi
            ENVIRONMENT="$2"
            shift 2
            ;;
        -p|--project)
            if [ -z "${2:-}" ]; then
                print_error "Project name is required"
                exit 1
            fi
            PROJECT="$2"
            shift 2
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
fi

# If specific environment is provided, decrypt only that environment
if [ -n "${ENVIRONMENT:-}" ]; then
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    base_dir="$script_dir"
    project=${PROJECT:-"gen-ai-template"}

    print_status "Decrypting specific environment: $ENVIRONMENT"

    if [ ! -d "$base_dir/$ENVIRONMENT" ]; then
        print_error "Environment directory does not exist: $base_dir/$ENVIRONMENT"
        exit 1
    fi

    if decrypt_directory "$base_dir/$ENVIRONMENT" "$ENVIRONMENT" "$project"; then
        print_success "Environment $ENVIRONMENT decrypted successfully!"
        exit 0
    else
        print_error "Failed to decrypt environment: $ENVIRONMENT"
        exit 1
    fi
fi

# Run main function
main "$@"
