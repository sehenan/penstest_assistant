#!/bin/bash

# SIATI Deployment and Monitoring Script
# This script helps deploy and monitor the SIATI application

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_info() {
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

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi

    print_success "Docker and Docker Compose are installed"
}

# Create necessary directories
create_directories() {
    print_info "Creating necessary directories..."

    mkdir -p data
    mkdir -p logs
    mkdir -p ssl
    mkdir -p data/knowledge_base
    mkdir -p data/model
    mkdir -p data/evaluation

    print_success "Directories created"
}

# Generate self-signed SSL certificates (for development)
generate_ssl_certs() {
    if [ ! -f "ssl/cert.pem" ] || [ ! -f "ssl/key.pem" ]; then
        print_info "Generating self-signed SSL certificates..."

        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout ssl/key.pem \
            -out ssl/cert.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

        print_success "SSL certificates generated"
    else
        print_warning "SSL certificates already exist"
    fi
}

# Build Docker images
build_images() {
    print_info "Building Docker images..."

    docker-compose build

    print_success "Docker images built successfully"
}

# Start services
start_services() {
    print_info "Starting SIATI services..."

    docker-compose up -d

    print_success "Services started successfully"
    print_info "Waiting for services to be ready..."

    # Wait for services to be healthy
    sleep 10

    # Check service status
    docker-compose ps
}

# Stop services
stop_services() {
    print_info "Stopping SIATI services..."

    docker-compose down

    print_success "Services stopped successfully"
}

# Restart services
restart_services() {
    print_info "Restarting SIATI services..."

    docker-compose restart

    print_success "Services restarted successfully"
}

# View logs
view_logs() {
    local service=$1

    if [ -z "$service" ]; then
        print_info "Showing logs for all services..."
        docker-compose logs -f
    else
        print_info "Showing logs for $service..."
        docker-compose logs -f "$service"
    fi
}

# Check service health
check_health() {
    print_info "Checking service health..."

    docker-compose ps

    echo ""
    print_info "Detailed health checks:"

    # Check SIATI API
    if curl -f -s http://localhost:8505/api/stats > /dev/null; then
        print_success "SIATI API is healthy"
    else
        print_error "SIATI API is not responding"
    fi

    # Check Ollama
    if curl -f -s http://localhost:11434/api/tags > /dev/null; then
        print_success "Ollama service is healthy"
    else
        print_error "Ollama service is not responding"
    fi

    # Check Redis
    if docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; then
        print_success "Redis service is healthy"
    else
        print_error "Redis service is not responding"
    fi
}

# Run tests
run_tests() {
    print_info "Running tests..."

    docker-compose exec siati python -m pytest tests/ -v

    print_success "Tests completed"
}

# Backup data
backup_data() {
    local backup_dir="backups/$(date +%Y%m%d_%H%M%S)"

    print_info "Creating backup in $backup_dir..."

    mkdir -p "$backup_dir"

    # Backup database
    if [ -f "data/pentest.db" ]; then
        cp data/pentest.db "$backup_dir/"
        print_success "Database backed up"
    fi

    # Backup models
    if [ -d "data/model" ]; then
        cp -r data/model "$backup_dir/"
        print_success "Models backed up"
    fi

    # Backup knowledge base
    if [ -d "data/knowledge_base" ]; then
        cp -r data/knowledge_base "$backup_dir/"
        print_success "Knowledge base backed up"
    fi

    print_success "Backup completed: $backup_dir"
}

# Restore data
restore_data() {
    local backup_dir=$1

    if [ -z "$backup_dir" ]; then
        print_error "Please specify backup directory"
        exit 1
    fi

    if [ ! -d "$backup_dir" ]; then
        print_error "Backup directory not found: $backup_dir"
        exit 1
    fi

    print_info "Restoring data from $backup_dir..."

    # Restore database
    if [ -f "$backup_dir/pentest.db" ]; then
        cp "$backup_dir/pentest.db" data/
        print_success "Database restored"
    fi

    # Restore models
    if [ -d "$backup_dir/model" ]; then
        rm -rf data/model
        cp -r "$backup_dir/model" data/
        print_success "Models restored"
    fi

    # Restore knowledge base
    if [ -d "$backup_dir/knowledge_base" ]; then
        rm -rf data/knowledge_base
        cp -r "$backup_dir/knowledge_base" data/
        print_success "Knowledge base restored"
    fi

    print_success "Data restored successfully"
}

# Clean up
cleanup() {
    print_info "Cleaning up..."

    # Stop and remove containers
    docker-compose down -v

    # Remove unused images
    docker image prune -f

    # Remove unused volumes
    docker volume prune -f

    print_success "Cleanup completed"
}

# Show usage
show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  setup           - Setup environment (directories, SSL, etc.)"
    echo "  build           - Build Docker images"
    echo "  start           - Start all services"
    echo "  stop            - Stop all services"
    echo "  restart         - Restart all services"
    echo "  logs [service]  - View logs (all services or specific service)"
    echo "  health          - Check service health"
    echo "  test            - Run tests"
    echo "  backup          - Backup data"
    echo "  restore [dir]   - Restore data from backup"
    echo "  cleanup         - Clean up containers and volumes"
    echo "  help            - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup"
    echo "  $0 start"
    echo "  $0 logs siati"
    echo "  $0 backup"
    echo "  $0 restore backups/20231201_120000"
}

# Main script logic
main() {
    check_docker

    case "${1:-help}" in
        setup)
            create_directories
            generate_ssl_certs
            ;;
        build)
            build_images
            ;;
        start)
            start_services
            ;;
        stop)
            stop_services
            ;;
        restart)
            restart_services
            ;;
        logs)
            view_logs "$2"
            ;;
        health)
            check_health
            ;;
        test)
            run_tests
            ;;
        backup)
            backup_data
            ;;
        restore)
            restore_data "$2"
            ;;
        cleanup)
            cleanup
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            print_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"