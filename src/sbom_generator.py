"""
SBOM Generator for creating SPDX-2.3 format SBOM from GitHub repositories
"""

import os
import logging
import json
import hashlib
import uuid
from datetime import datetime
import shutil
from tqdm import tqdm
from spdx.document import Document, License
from spdx.version import Version
from spdx.creationinfo import Person, Organization, Tool
from spdx.package import Package
from spdx.file import File
from spdx.checksum import Algorithm
from spdx.utils import SPDXNone, NoAssert, UnKnown

from src.utils import (
    clean_temp_directory, 
    create_repo_temp_dir, 
    detect_programming_languages,
    get_package_manager_files
)

logger = logging.getLogger(__name__)

class SBOMGenerator:
    """SBOM Generator for creating SPDX-2.3 format SBOM"""
    
    def __init__(self, github_client, temp_dir, namespace_prefix, 
                 creator_name, creator_email, output_format="json"):
        """
        Initialize SBOM Generator
        
        Args:
            github_client: GitHub client instance
            temp_dir (str): Temporary directory path
            namespace_prefix (str): SPDX document namespace prefix
            creator_name (str): Creator name
            creator_email (str): Creator email
            output_format (str): Output format (json or tag-value)
        """
        self.github_client = github_client
        self.temp_dir = temp_dir
        self.namespace_prefix = namespace_prefix
        self.creator_name = creator_name
        self.creator_email = creator_email
        self.output_format = output_format
        self.repo_temp_dir = None
        logger.info("SBOM Generator initialized")
    
    def generate_sbom(self, org, repo, output_file):
        """
        Generate SBOM for a GitHub repository
        
        Args:
            org (str): Organization name
            repo (str): Repository name
            output_file (str): Output file path
            
        Returns:
            str: Path to generated SBOM file
        """
        try:
            # Create temporary directory for repository
            self.repo_temp_dir = create_repo_temp_dir(self.temp_dir, org, repo)
            logger.info(f"Created temporary directory for repository: {self.repo_temp_dir}")
            
            # Download repository
            repo_dir = self.github_client.download_repository(org, repo, self.repo_temp_dir)
            logger.info(f"Downloaded repository to {repo_dir}")
            
            # Get repository metadata
            metadata = self.github_client.get_repository_metadata(org, repo)
            logger.info(f"Retrieved repository metadata")
            
            # Create SPDX document
            document = self._create_spdx_document(org, repo, metadata)
            logger.info("Created SPDX document")
            
            # Create main package
            main_package = self._create_main_package(org, repo, repo_dir, metadata)
            document.add_package(main_package)
            logger.info("Added main package to SPDX document")
            
            # Add files to package
            self._add_files_to_package(main_package, repo_dir)
            logger.info("Added files to main package")
            
            # Add dependencies
            self._add_dependencies(main_package, repo_dir)
            logger.info("Added dependencies to main package")
            
            # Ensure output directory exists
            output_dir = os.path.dirname(os.path.abspath(output_file))
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            # Write SBOM to file
            self._write_sbom(document, output_file)
            logger.info(f"SBOM written to {output_file}")
            
            return output_file
        except Exception as e:
            logger.error(f"Error generating SBOM: {e}", exc_info=True)
            raise
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.repo_temp_dir and os.path.exists(self.repo_temp_dir):
            clean_temp_directory(self.repo_temp_dir)
            logger.info(f"Cleaned up temporary directory: {self.repo_temp_dir}")
    
    def _create_spdx_document(self, org, repo, metadata):
        """Create SPDX document"""
        # Create document namespace
        doc_namespace = f"{self.namespace_prefix}/{org}/{repo}-{uuid.uuid4()}"
        
        # Create document
        document = Document(
            version=Version(2, 3),
            data_license=License.from_identifier("CC0-1.0"),
            name=f"{org}/{repo} SBOM",
            namespace=doc_namespace,
            spdx_id="SPDXRef-DOCUMENT",
            comment=f"SBOM for GitHub repository {org}/{repo}",
            document_describes=[]
        )
        
        # Add creation info
        document.creation_info.set_created_now()
        document.creation_info.add_creator(Person(f"{self.creator_name} ({self.creator_email})"))
        document.creation_info.add_creator(Tool("SBOM-Generator"))
        
        return document
    
    def _create_main_package(self, org, repo, repo_dir, metadata):
        """Create main package for the repository"""
        # Create package
        package = Package(
            name=metadata["name"],
            spdx_id=f"SPDXRef-Package-{metadata['name']}",
            download_location=metadata["clone_url"],
            version=f"commit-{metadata['default_branch']}",
            file_name=None,
            supplier=NoAssert(),
            originator=Organization(f"Organization: {org}")
        )
        
        # Set package properties
        package.description = metadata["description"] or "No description provided"
        package.homepage = metadata["html_url"]
        package.cr_text = NoAssert()
        
        # Set license info
        if metadata["license"]:
            package.license_declared = License.from_identifier(metadata["license"])
        else:
            package.license_declared = NoAssert()
        
        package.license_concluded = NoAssert()
        package.license_comment = "License information from GitHub repository metadata"
        
        # Set copyright text
        package.copyright_text = NoAssert()
        
        # Set verification code (placeholder, will be updated when files are added)
        package.verif_code = "0000000000000000000000000000000000000000"
        
        # Detect programming languages
        languages = detect_programming_languages(repo_dir)
        if languages:
            package.comment = f"Primary languages: {', '.join(languages.keys())}"
        
        return package
    
    def _add_files_to_package(self, package, repo_dir):
        """Add files to package"""
        files = []
        verification_code_files = []
        
        # Walk through repository directory
        exclude_dirs = ['.git', 'node_modules', '__pycache__', 'dist', 'build', 'target']
        include_extensions = [
            '.py', '.js', '.java', '.go', '.rb', '.c', '.cpp', '.h', '.cs', 
            '.php', '.ts', '.sh', '.md', '.yaml', '.yml', '.json', '.xml', 
            '.html', '.css', '.txt', '.rs', '.kt', '.swift', '.scala'
        ]
        
        for root, dirs, filenames in os.walk(repo_dir):
            # Modify dirs in-place to exclude certain directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for filename in filenames:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, repo_dir)
                
                # Check file extension
                _, ext = os.path.splitext(filename)
                if ext.lower() not in include_extensions:
                    continue
                
                try:
                    # Create SPDX file
                    spdx_file = self._create_spdx_file(file_path, rel_path)
                    files.append(spdx_file)
                    
                    # Add file to verification code
                    with open(file_path, 'rb') as f:
                        sha1 = hashlib.sha1(f.read()).hexdigest()
                        verification_code_files.append(sha1)
                except Exception as e:
                    logger.warning(f"Error processing file {rel_path}: {e}")
        
        # Add files to package
        for spdx_file in tqdm(files, desc="Adding files to SBOM"):
            package.add_file(spdx_file)
        
        # Update verification code
        if verification_code_files:
            verification_code_files.sort()
            verification_code_string = ''.join(verification_code_files)
            package.verif_code = hashlib.sha1(verification_code_string.encode('utf-8')).hexdigest()
    
    def _create_spdx_file(self, file_path, rel_path):
        """Create SPDX file"""
        # Create file
        spdx_file = File(
            name=rel_path,
            spdx_id=f"SPDXRef-File-{hashlib.md5(rel_path.encode('utf-8')).hexdigest()}"
        )
        
        # Add checksums
        with open(file_path, 'rb') as f:
            content = f.read()
            spdx_file.add_checksum(Algorithm("SHA1", hashlib.sha1(content).hexdigest()))
            spdx_file.add_checksum(Algorithm("SHA256", hashlib.sha256(content).hexdigest()))
            spdx_file.add_checksum(Algorithm("MD5", hashlib.md5(content).hexdigest()))
        
        # Set license info
        spdx_file.license_concluded = NoAssert()
        spdx_file.license_info_in_file = [NoAssert()]
        spdx_file.copyright_text = NoAssert()
        
        return spdx_file
    
    def _add_dependencies(self, package, repo_dir):
        """Add dependencies to package"""
        # Get package manager files
        package_files = get_package_manager_files(repo_dir)
        
        if not package_files:
            logger.info("No package manager files found")
            return
        
        # Process each package manager file
        for manager, file_path in package_files:
            logger.info(f"Processing {manager} dependencies from {file_path}")
            
            # Add relationship to package
            abs_path = os.path.join(repo_dir, file_path)
            if os.path.exists(abs_path):
                # This is a simplified approach - in a real implementation,
                # you would parse the dependency file and add each dependency
                # as a separate package with proper relationships
                package.add_comment(f"Contains {manager} dependencies defined in {file_path}")
    
    def _write_sbom(self, document, output_file):
        """Write SBOM to file"""
        # Ensure output directory exists
        output_dir = os.path.dirname(os.path.abspath(output_file))
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Write SBOM to file
        if self.output_format.lower() == "json":
            # For simplicity, we're using a basic JSON serialization
            # In a real implementation, you would use the proper SPDX serialization
            with open(output_file, 'w', encoding='utf-8') as f:
                # This is a placeholder for actual SPDX JSON serialization
                # In a real implementation, you would use spdx-tools to serialize the document
                json.dump({
                    "spdxVersion": "SPDX-2.3",
                    "dataLicense": "CC0-1.0",
                    "SPDXID": document.spdx_id,
                    "name": document.name,
                    "documentNamespace": document.namespace,
                    "creationInfo": {
                        "created": document.creation_info.created,
                        "creators": [c.to_value() for c in document.creation_info.creators],
                    },
                    "packages": [
                        {
                            "name": p.name,
                            "SPDXID": p.spdx_id,
                            "downloadLocation": p.download_location,
                            "filesAnalyzed": True,
                            "licenseConcluded": "NOASSERTION",
                            "licenseDeclared": "NOASSERTION",
                            "copyrightText": "NOASSERTION",
                            "description": p.description,
                            "comment": p.comment,
                            "versionInfo": p.version,
                            "supplier": "NOASSERTION",
                            "homepage": p.homepage,
                        } for p in document.packages
                    ],
                    # Files would be included here in a real implementation
                }, f, indent=2)
        else:
            # Tag-value format (not implemented in this example)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"SPDXVersion: {document.spdx_version}\n")
                f.write(f"DataLicense: {document.data_license.identifier}\n")
                f.write(f"SPDXID: {document.spdx_id}\n")
                f.write(f"DocumentName: {document.name}\n")
                f.write(f"DocumentNamespace: {document.namespace}\n")
                # More tag-value pairs would be written here in a real implementation 