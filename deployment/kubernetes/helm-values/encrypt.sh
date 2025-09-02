#!/bin/bash
# Run './encrypt.sh' and the script will handle everything automatically.

# Encrypt files only if the decrypted content differs from the existing plaintext file
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

# Function to compare files and check if encryption is needed
needs_encryption() {
    local enc_file=$1
    local plain_file=$2

    # If encrypted file doesn't exist, we need to encrypt
    if [ ! -f "$enc_file" ]; then
        return 0
    fi

    # If plain file doesn't exist, we can't compare
    if [ ! -f "$plain_file" ]; then
        print_warning "Plain file doesn't exist: $plain_file"
        return 1
    fi

    # Create a temporary file for decryption
    local temp_decrypted
    temp_decrypted=$(mktemp)
    local needs_encrypt=false

    # Try to decrypt the existing encrypted file
    if gcloud kms decrypt \
        --ciphertext-file="$enc_file" \
        --plaintext-file="$temp_decrypted" \
        --location=global \
        --keyring=cloudbuild \
        --key="${project}-${env_key}" >/dev/null 2>&1; then

        # Compare the decrypted content with the plain file
        if ! cmp -s "$temp_decrypted" "$plain_file"; then
            needs_encrypt=true
            print_status "Content differs, encryption needed"
        else
            print_status "Content is identical, skipping encryption"
        fi
    else
        # If decryption fails, we need to encrypt
        needs_encrypt=true
        print_warning "Could not decrypt existing file, will re-encrypt"
    fi

    # Clean up temporary file
    rm -f "$temp_decrypted"

    if [ "$needs_encrypt" = true ]; then
        return 0
    else
        return 1
    fi
}

# Function to encrypt a single file
encrypt_file() {
    local filepath=$1
    local environment=$2
    local project=${3:-"gen-ai-template"}

    local env_key
    env_key=$(get_env_key "$environment")
    local encrypted_file="${filepath}.enc"

    print_status "Checking: $filepath"
    print_status "Environment: $environment (key: $env_key)"

    # Check if encryption is needed
    if [ "${FORCE_ENCRYPT:-false}" = "true" ] || needs_encryption "$encrypted_file" "$filepath"; then
        print_status "Encrypting: $filepath"

        if gcloud kms encrypt \
            --plaintext-file="$filepath" \
            --ciphertext-file="$encrypted_file" \
            --location=global \
            --keyring=cloudbuild \
            --key="${project}-${env_key}"; then
            print_success "Successfully encrypted: $filepath"
        else
            print_error "Failed to encrypt: $filepath"
            return 1
        fi
    else
        print_success "No encryption needed for: $filepath"
    fi
}

# Function to encrypt all files in a directory
encrypt_directory() {
    local dir_path=$1
    local environment=$2
    local project=${3:-"gen-ai-template"}

    if [ ! -d "$dir_path" ]; then
        print_warning "Directory does not exist: $dir_path"
        return 0
    fi

    print_status "Scanning directory: $dir_path"

    # Find all files that should be encrypted (exclude .enc files and common non-secret files)
    local files_to_encrypt
    files_to_encrypt=$(find "$dir_path" -type f \( -name 'values-secret.yaml' -o -name 'secret.yaml' -o -name '*.secret' -o -name '*.key' -o -name '*.pem' -o -name '*.crt' \) ! -name '*.enc')

    if [ -z "$files_to_encrypt" ]; then
        print_status "No files to encrypt found in: $dir_path"
        return 0
    fi

    local success_count=0
    local total_count=0
    local encrypted_count=0

    while IFS= read -r -d '' filepath; do
        total_count=$((total_count + 1))
        if encrypt_file "$filepath" "$environment" "$project"; then
            success_count=$((success_count + 1))
            # Check if file was actually encrypted (not skipped)
            if [ -f "${filepath}.enc" ] && [ "$(stat -c %Y "${filepath}.enc" 2>/dev/null || stat -f %m "${filepath}.enc" 2>/dev/null)" -gt "$(date +%s -d '1 minute ago')" ]; then
                encrypted_count=$((encrypted_count + 1))
            fi
        fi
    done < <(find "$dir_path" -type f \( -name 'values-secret.yaml' -o -name 'secret.yaml' -o -name '*.secret' -o -name '*.key' -o -name '*.pem' -o -name '*.crt' \) ! -name '*.enc' -print0)

    print_status "Encryption summary for $dir_path: $success_count/$total_count files processed, $encrypted_count actually encrypted"

    if [ $success_count -ne $total_count ]; then
        return 1
    fi
}

# Function to clean up orphaned .enc files
cleanup_orphaned_enc_files() {
    local dir_path=$1
    local environment=$2
    local project=${3:-"gen-ai-template"}

    local env_key
    env_key=$(get_env_key "$environment")

    print_status "Checking for orphaned .enc files in: $dir_path"

    local orphaned_count=0

    while IFS= read -r -d '' enc_file; do
        local plain_file="${enc_file::-4}"  # Remove .enc extension

        # If plain file doesn't exist, the .enc file is orphaned
        if [ ! -f "$plain_file" ]; then
            print_warning "Found orphaned .enc file: $enc_file (no corresponding plain file)"
            if [ "${CLEANUP_ORPHANED:-false}" = "true" ]; then
                if rm "$enc_file"; then
                    print_success "Removed orphaned file: $enc_file"
                    orphaned_count=$((orphaned_count + 1))
                else
                    print_error "Failed to remove orphaned file: $enc_file"
                fi
            fi
        fi
    done < <(find "$dir_path" -type f -name '*.enc' -print0)

    if [ $orphaned_count -gt 0 ]; then
        print_status "Cleaned up $orphaned_count orphaned .enc files"
    elif [ "${CLEANUP_ORPHANED:-false}" = "true" ]; then
        print_status "No orphaned .enc files found"
    fi
}

# Main function
main() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local base_dir="$script_dir"
    local project=${PROJECT:-"gen-ai-template"}

    print_status "Starting encryption process..."
    print_status "Base directory: $base_dir"
    print_status "Project: $project"
    print_status "Cleanup orphaned files: ${CLEANUP_ORPHANED:-false}"

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

        # Clean up orphaned files first if requested
        if [ "${CLEANUP_ORPHANED:-false}" = "true" ]; then
            cleanup_orphaned_enc_files "$base_dir/$env_dir" "$env_dir" "$project"
        fi

        if ! encrypt_directory "$base_dir/$env_dir" "$env_dir" "$project"; then
            print_error "Failed to encrypt some files in environment: $env_dir"
            overall_success=false
        fi
    done

    if [ "$overall_success" = true ]; then
        print_success "All files processed successfully!"
        exit 0
    else
        print_error "Some files failed to process. Please check the errors above."
        exit 1
    fi
}

# Handle command line arguments
if [ $# -gt 0 ]; then
    case "$1" in
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Encrypt files only if content differs from existing encrypted files"
            echo ""
            echo "Options:"
            echo "  -h, --help           Show this help message"
            echo "  -e, --env            Encrypt specific environment only"
            echo "  -p, --project        Specify project name (default: gen-ai-template)"
            echo "  -c, --cleanup        Clean up orphaned .enc files"
            echo "  -f, --force          Force encryption of all files (ignore differences)"
            echo ""
            echo "Environment variables:"
            echo "  PROJECT              Project name for KMS key (default: gen-ai-template)"
            echo "  CLEANUP_ORPHANED     Set to 'true' to remove orphaned .enc files"
            echo "  FORCE_ENCRYPT        Set to 'true' to force encryption of all files"
            echo ""
            echo "Examples:"
            echo "  $0                           # Encrypt changed files in all environments"
            echo "  $0 -e dev                    # Encrypt changed files in dev environment"
            echo "  $0 -c                        # Clean up orphaned files and encrypt"
            echo "  PROJECT=my-project $0        # Use custom project name"
            echo "  FORCE_ENCRYPT=true $0        # Force encryption of all files"
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
        -c|--cleanup)
            CLEANUP_ORPHANED="true"
            shift
            ;;
        -f|--force)
            export FORCE_ENCRYPT="true"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
fi

# If specific environment is provided, encrypt only that environment
if [ -n "${ENVIRONMENT:-}" ]; then
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    base_dir="$script_dir"
    project=${PROJECT:-"gen-ai-template"}

    print_status "Encrypting specific environment: $ENVIRONMENT"

    if [ ! -d "$base_dir/$ENVIRONMENT" ]; then
        print_error "Environment directory does not exist: $base_dir/$ENVIRONMENT"
        exit 1
    fi

    # Clean up orphaned files first if requested
    if [ "${CLEANUP_ORPHANED:-false}" = "true" ]; then
        cleanup_orphaned_enc_files "$base_dir/$ENVIRONMENT" "$ENVIRONMENT" "$project"
    fi

    if encrypt_directory "$base_dir/$ENVIRONMENT" "$ENVIRONMENT" "$project"; then
        print_success "Environment $ENVIRONMENT processed successfully!"
        exit 0
    else
        print_error "Failed to process environment: $ENVIRONMENT"
        exit 1
    fi
fi

# Run main function
main "$@"
