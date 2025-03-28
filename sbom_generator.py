#!/usr/bin/env python3
"""
SBOM Generator - Generate SPDX-2.3 format SBOM from GitHub repositories
"""

import os
import sys
import logging

try:
    import click
    import yaml
    from src.github_client import GitHubClient
    from src.sbom_generator import SBOMGenerator
    from src.utils import setup_logging, ensure_temp_directory
except ModuleNotFoundError as e:
    print(f"Error: Missing dependency: {e}")
    print("\nPlease ensure all dependencies are installed. Try running:")
    print("  pip install -r requirements.txt")
    print("\nIf you are using a virtual environment, make sure it is activated:")
    print("  On Windows: venv\\Scripts\\activate")
    print("  On Unix/Linux/MacOS: source venv/bin/activate")
    print("\nAlternatively, you can run setup_venv.bat (Windows) or setup_venv.sh (Unix/Linux/MacOS) to set up the virtual environment.")
    sys.exit(1)

# Setup logging
logger = logging.getLogger(__name__)

def load_config():
    """Load configuration from config.yaml file"""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml')
    
    try:
        with open(config_path, 'r') as config_file:
            return yaml.safe_load(config_file)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        print(f"Error: Configuration file not found: {config_path}")
        print("Please create a config.yaml file based on the template.")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {e}")
        print(f"Error parsing configuration file: {e}")
        sys.exit(1)

@click.command()
@click.option('--org', '-o', help='GitHub organization name')
@click.option('--repo', '-r', help='GitHub repository name')
@click.option('--output', '-f', help='Output file path (default: output/<repo>-sbom.spdx.json)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--commit', '-c', help='Specific commit hash to generate SBOM for')
def main(org, repo, output, verbose, commit):
    """Generate SBOM for a GitHub repository in SPDX-2.3 format"""
    # Setup logging level
    log_level = logging.DEBUG if verbose else logging.INFO
    setup_logging(log_level)
    
    # Load configuration
    config = load_config()
    
    # Ensure temp directory exists
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                           config['temp']['directory'])
    ensure_temp_directory(temp_dir)
    
    # Ensure output directory exists
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"Created output directory: {output_dir}")
    
    # If org or repo not provided, prompt for them
    if not org:
        org = click.prompt("Enter GitHub organization name")
    
    if not repo:
        repo = click.prompt("Enter GitHub repository name")
    
    # Set default output file if not specified
    if not output:
        output = os.path.join(output_dir, f"{repo}-sbom.spdx.json")
    elif not os.path.isabs(output):
        # If it's a relative path, make it relative to the output directory
        output = os.path.join(output_dir, output)
    
    # Initialize GitHub client
    github_token = config.get('github', {}).get('token')
    if not github_token or github_token == "your-github-token-here":
        logger.warning("GitHub token not configured. Some repositories may not be accessible.")
        print("Warning: GitHub token not configured in config.yaml")
        github_token = click.prompt("Enter GitHub token (leave empty to continue without token)", 
                                   default="", show_default=False)
    
    github_client = GitHubClient(github_token, config.get('github', {}).get('rate_limit_wait', True))
    
    # Initialize SBOM generator
    sbom_generator = SBOMGenerator(
        github_client=github_client,
        temp_dir=temp_dir,
        namespace_prefix=config['sbom']['namespace_prefix'],
        creator_name=config['sbom']['creator_name'],
        creator_email=config['sbom']['creator_email'],
        output_format=config['sbom']['output_format']
    )
    
    try:
        # Generate SBOM
        print(f"Generating SBOM for {org}/{repo}" + (f" at commit {commit}" if commit else "..."))
        sbom_file = sbom_generator.generate_sbom(org, repo, output, commit)
        print(f"SBOM generated successfully: {sbom_file}")
        print(f"SBOM file saved at: {os.path.abspath(sbom_file)}")
    except Exception as e:
        logger.error(f"Error generating SBOM: {e}", exc_info=True)
        print(f"Error generating SBOM: {e}")
        sys.exit(1)
    finally:
        # Clean up temporary files if configured
        if config['temp']['cleanup_after']:
            sbom_generator.cleanup()

if __name__ == "__main__":
    main() 