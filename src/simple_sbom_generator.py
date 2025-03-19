"""
简化版 SBOM 生成器，不依赖于 spdx-tools 库
"""

import os
import logging
import json
import hashlib
import uuid
import re
from datetime import datetime
import shutil
from tqdm import tqdm
import yaml
from src.utils import (
    clean_temp_directory, 
    create_repo_temp_dir, 
    detect_programming_languages,
    get_package_manager_files,
    ensure_temp_directory,
    get_timestamp
)

logger = logging.getLogger(__name__)

def import_helper(module_name):
    """尝试导入可选模块，如果不存在则返回 None"""
    try:
        return __import__(module_name)
    except ImportError:
        return None

# 导入可选的依赖解析模块
toml = import_helper('toml')

class SimpleSBOMGenerator:
    """简化版 SBOM 生成器，生成 SPDX-2.3 格式的 SBOM"""
    
    def __init__(self, github_client, temp_dir, namespace_prefix, 
                 creator_name, creator_email, output_format="json"):
        """
        初始化 SBOM 生成器
        
        Args:
            github_client: GitHub 客户端实例
            temp_dir (str): 临时目录路径
            namespace_prefix (str): SPDX 文档命名空间前缀
            creator_name (str): 创建者姓名
            creator_email (str): 创建者邮箱
            output_format (str): 输出格式 (json 或 tag-value)
        """
        self.github_client = github_client
        self.temp_dir = temp_dir
        self.namespace_prefix = namespace_prefix
        self.creator_name = creator_name
        self.creator_email = creator_email
        self.output_format = output_format
        self.repo_temp_dir = None
        # 设置文件扩展名过滤器 - 这些是我们感兴趣的文件类型
        self.include_extensions = [
            '.py', '.js', '.java', '.go', '.rb', '.c', '.cpp', '.h', '.cs', 
            '.php', '.ts', '.sh', '.md', '.yaml', '.yml', '.json', '.xml', 
            '.html', '.css', '.txt', '.rs', '.kt', '.swift', '.scala'
        ]
        # 要排除的目录名
        self.exclude_dirs = ['.git', 'node_modules', '__pycache__', 'dist', 'build', 'target', '.idea', '.vscode']
        logger.info("简化版 SBOM 生成器已初始化")
    
    def generate_sbom(self, org, repo, output_file):
        """
        为 GitHub 仓库生成 SBOM
        
        Args:
            org (str): 组织名称
            repo (str): 仓库名称
            output_file (str): 输出文件路径
            
        Returns:
            str: 生成的 SBOM 文件路径
        """
        try:
            # 为仓库创建临时目录
            self.repo_temp_dir = create_repo_temp_dir(self.temp_dir, org, repo)
            logger.info(f"为仓库创建了临时目录: {self.repo_temp_dir}")
            
            # 下载仓库
            repo_dir = self.github_client.download_repository(org, repo, self.repo_temp_dir)
            logger.info(f"下载仓库到 {repo_dir}")
            
            # 获取仓库元数据
            metadata = self.github_client.get_repository_metadata(org, repo)
            logger.info(f"获取仓库元数据")
            
            # 创建 SBOM 文档
            sbom_document = self._create_sbom_document(org, repo, repo_dir, metadata)
            logger.info("创建 SBOM 文档")
            
            # 确保输出目录存在
            output_dir = os.path.dirname(os.path.abspath(output_file))
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            # 写入 SBOM 到文件
            self._write_sbom(sbom_document, output_file)
            logger.info(f"SBOM 已写入到 {output_file}")
            
            return output_file
        except Exception as e:
            logger.error(f"生成 SBOM 时出错: {e}", exc_info=True)
            raise
    
    def cleanup(self):
        """清理临时文件"""
        if self.repo_temp_dir and os.path.exists(self.repo_temp_dir):
            clean_temp_directory(self.repo_temp_dir)
            logger.info(f"清理临时目录: {self.repo_temp_dir}")
    
    def _create_sbom_document(self, org, repo, repo_dir, metadata):
        """创建 SBOM 文档"""
        timestamp = datetime.utcnow().isoformat() + 'Z'
        doc_namespace = f"{self.namespace_prefix}/{org}/{repo}-{uuid.uuid4()}"
        
        # 检测编程语言
        languages = detect_programming_languages(repo_dir)
        
        # 获取包管理器文件
        package_files = get_package_manager_files(repo_dir)
        
        # 创建文件列表（应用过滤器）
        files = []
        
        # 遍历仓库目录
        logger.info("开始收集文件信息...")
        for root, dirs, filenames in os.walk(repo_dir):
            # 原地修改 dirs 列表以跳过某些目录
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs]
            
            for filename in filenames:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, repo_dir)
                
                # 检查文件扩展名是否在我们关心的列表中
                _, ext = os.path.splitext(filename)
                if ext.lower() not in self.include_extensions:
                    continue
                
                # 跳过 .git 目录
                if any(excluded in rel_path.split(os.path.sep) for excluded in self.exclude_dirs):
                    continue
                
                try:
                    file_info = self._create_file_info(file_path, rel_path)
                    files.append(file_info)
                except Exception as e:
                    logger.warning(f"处理文件 {rel_path} 时出错: {e}")
        
        logger.info(f"收集了 {len(files)} 个文件的信息")
        
        # 解析依赖项
        packages = [
            {
                "name": metadata["name"],
                "SPDXID": f"SPDXRef-Package-{metadata['name']}",
                "downloadLocation": metadata["clone_url"],
                "filesAnalyzed": True,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": metadata["license"] if metadata["license"] else "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "description": metadata["description"] or "No description provided",
                "comment": f"Primary languages: {', '.join(languages.keys()) if languages else 'Unknown'}",
                "versionInfo": f"commit-{metadata['default_branch']}",
                "supplier": f"Organization: {org}",
                "homepage": metadata["html_url"]
            }
        ]
        
        # 添加依赖关系信息
        dependencies = []
        if package_files:
            logger.info(f"发现 {len(package_files)} 个包管理器文件，开始解析依赖项...")
            
            for manager, file_path in package_files:
                abs_path = os.path.join(repo_dir, file_path)
                if os.path.exists(abs_path):
                    extracted_deps = self._extract_dependencies(manager, abs_path)
                    if extracted_deps:
                        dependencies.extend(extracted_deps)
                        logger.info(f"从 {file_path} 中提取了 {len(extracted_deps)} 个依赖项")
        
        # 将依赖项添加到 packages 列表中
        for dep in dependencies:
            packages.append(dep)
        
        logger.info(f"总共收集了 {len(packages)} 个包的信息")
        
        # 创建 SBOM 文档
        sbom_document = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{org}/{repo} SBOM",
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": timestamp,
                "creators": [
                    f"Person: {self.creator_name} ({self.creator_email})",
                    "Tool: SimpleSBOMGenerator"
                ],
                "licenseListVersion": "3.19"
            },
            "packages": packages,
            "files": files,
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relatedSpdxElement": f"SPDXRef-Package-{metadata['name']}",
                    "relationshipType": "DESCRIBES"
                }
            ]
        }
        
        # 添加包之间的关系
        for dep in dependencies:
            sbom_document["relationships"].append({
                "spdxElementId": f"SPDXRef-Package-{metadata['name']}",
                "relatedSpdxElement": dep["SPDXID"],
                "relationshipType": "DEPENDS_ON"
            })
        
        return sbom_document
    
    def _create_file_info(self, file_path, rel_path):
        """创建文件信息"""
        file_id = hashlib.md5(rel_path.encode('utf-8')).hexdigest()
        
        with open(file_path, 'rb') as f:
            content = f.read()
            sha1 = hashlib.sha1(content).hexdigest()
            sha256 = hashlib.sha256(content).hexdigest()
            md5 = hashlib.md5(content).hexdigest()
        
        return {
            "fileName": rel_path,
            "SPDXID": f"SPDXRef-File-{file_id}",
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": sha1},
                {"algorithm": "SHA256", "checksumValue": sha256},
                {"algorithm": "MD5", "checksumValue": md5}
            ],
            "licenseConcluded": "NOASSERTION",
            "licenseInfoInFiles": ["NOASSERTION"],
            "copyrightText": "NOASSERTION"
        }
    
    def _extract_dependencies(self, manager, file_path):
        """
        从包管理器文件中提取依赖项
        
        Args:
            manager (str): 包管理器名称
            file_path (str): 包管理器文件路径
            
        Returns:
            list: 依赖项列表
        """
        dependencies = []
        
        try:
            if manager == 'Python':
                if file_path.endswith('requirements.txt'):
                    dependencies.extend(self._parse_requirements_txt(file_path))
                elif file_path.endswith('setup.py'):
                    dependencies.extend(self._parse_setup_py(file_path))
                elif file_path.endswith('Pipfile'):
                    dependencies.extend(self._parse_pipfile(file_path))
                elif file_path.endswith('pyproject.toml'):
                    dependencies.extend(self._parse_pyproject_toml(file_path))
            
            elif manager == 'JavaScript/Node.js':
                if file_path.endswith('package.json'):
                    dependencies.extend(self._parse_package_json(file_path))
            
            elif manager == 'Go':
                if file_path.endswith('go.mod'):
                    dependencies.extend(self._parse_go_mod(file_path))
            
            elif manager == 'Java':
                if file_path.endswith('pom.xml'):
                    dependencies.extend(self._parse_pom_xml(file_path))
                elif file_path.endswith('.gradle') or file_path.endswith('.gradle.kts'):
                    dependencies.extend(self._parse_gradle(file_path))
            
            # 可以根据需要添加更多的包管理器解析逻辑
            
        except Exception as e:
            logger.warning(f"解析依赖项文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_requirements_txt(self, file_path):
        """解析 requirements.txt 文件"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    # 删除注释和空格
                    line = line.split('#')[0].strip()
                    if not line or line.startswith('-') or line.startswith('--'):
                        continue
                    
                    # 处理包名和版本
                    parts = re.split(r'[<>=~]', line, 1)
                    package_name = parts[0].strip()
                    
                    if len(parts) > 1:
                        version = line[len(package_name):].strip()
                    else:
                        version = "NOASSERTION"
                    
                    dependencies.append({
                        "name": package_name,
                        "SPDXID": f"SPDXRef-Package-{package_name}",
                        "versionInfo": version,
                        "downloadLocation": f"https://pypi.org/project/{package_name}/",
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                        "supplier": "Organization: PyPI"
                    })
        except Exception as e:
            logger.warning(f"解析 requirements.txt 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_package_json(self, file_path):
        """解析 package.json 文件"""
        dependencies = []
        
        try:
            # 先检查文件是否为空
            if os.path.getsize(file_path) == 0:
                logger.warning(f"package.json 文件 {file_path} 为空")
                return dependencies
                
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 规范化处理 JSON 内容
            # 1. 移除注释 (JSON 标准不支持注释，但有些项目会添加)
            content = self._normalize_json(content)
                
            try:
                data = json.loads(content)
            except json.JSONDecodeError as e:
                logger.warning(f"解析 package.json 文件 {file_path} 时出错: {e}")
                return dependencies
                
            # 处理依赖项
            dep_sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
            
            for section in dep_sections:
                if section in data and isinstance(data[section], dict):
                    for name, version in data[section].items():
                        if not isinstance(name, str) or not name:
                            continue
                            
                        if not isinstance(version, str):
                            version = str(version)
                            
                        dependencies.append({
                            "name": name,
                            "SPDXID": f"SPDXRef-Package-{name}",
                            "versionInfo": version,
                            "downloadLocation": f"https://www.npmjs.com/package/{name}",
                            "licenseConcluded": "NOASSERTION",
                            "licenseDeclared": "NOASSERTION",
                            "copyrightText": "NOASSERTION",
                            "supplier": "Organization: npm"
                        })
        except Exception as e:
            logger.warning(f"解析 package.json 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _normalize_json(self, content):
        """
        规范化 JSON 内容，移除注释和处理其他非标准JSON格式
        
        Args:
            content (str): JSON 内容
            
        Returns:
            str: 规范化后的 JSON 内容
        """
        # 移除单行注释 (//...)
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        
        # 移除多行注释 (/* ... */)
        content = re.sub(r'/\*[\s\S]*?\*/', '', content)
        
        # 移除尾随逗号，这在标准JSON中是不允许的，但在一些项目中使用
        content = re.sub(r',\s*([}\]])', r'\1', content)
        
        return content
    
    def _parse_go_mod(self, file_path):
        """解析 go.mod 文件"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # 规范化处理文件内容，删除注释
                content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
                
                # 处理多行 require 块，匹配整个块包括括号
                require_block_matches = re.finditer(r'require\s*\(\s*([\s\S]*?)\s*\)', content)
                for block_match in require_block_matches:
                    # 提取块内容（不包括require和括号）
                    block_content = block_match.group(1).strip()
                    
                    # 按行处理每个依赖项
                    for line in block_content.split('\n'):
                        line = line.strip()
                        if not line or line.startswith('//'):
                            continue
                        
                        # 匹配依赖项路径和版本
                        # 格式应该是: module_path version [// comment]
                        match = re.match(r'([^\s]+)\s+([^\s/]+)(?:\s*//.*)?$', line)
                        if match:
                            name = match.group(1)
                            version = match.group(2)
                            
                            dependencies.append({
                                "name": name,
                                "SPDXID": f"SPDXRef-Package-{hashlib.md5(name.encode()).hexdigest()}",
                                "versionInfo": version,
                                "downloadLocation": f"https://pkg.go.dev/{name}",
                                "licenseConcluded": "NOASSERTION",
                                "licenseDeclared": "NOASSERTION",
                                "copyrightText": "NOASSERTION",
                                "supplier": "Organization: Go Module"
                            })
                
                # 处理单行 require 语句
                # 格式是: require module_path version
                single_requires = re.finditer(r'require\s+([^\s\(]+)\s+([^\s\(]+)', content)
                for req in single_requires:
                    name = req.group(1)
                    version = req.group(2)
                    
                    dependencies.append({
                        "name": name,
                        "SPDXID": f"SPDXRef-Package-{hashlib.md5(name.encode()).hexdigest()}",
                        "versionInfo": version,
                        "downloadLocation": f"https://pkg.go.dev/{name}",
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                        "supplier": "Organization: Go Module"
                    })
        except Exception as e:
            logger.warning(f"解析 go.mod 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_setup_py(self, file_path):
        """解析 setup.py 文件（简化版本）"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # 查找 install_requires 列表
                match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
                if match:
                    deps_str = match.group(1)
                    
                    # 提取每个依赖项
                    for dep in re.finditer(r'[\'"]([^\'"]+)[\'"]', deps_str):
                        req = dep.group(1).strip()
                        
                        # 处理包名和版本
                        parts = re.split(r'[<>=~]', req, 1)
                        package_name = parts[0].strip()
                        
                        if len(parts) > 1:
                            version = req[len(package_name):].strip()
                        else:
                            version = "NOASSERTION"
                        
                        dependencies.append({
                            "name": package_name,
                            "SPDXID": f"SPDXRef-Package-{package_name}",
                            "versionInfo": version,
                            "downloadLocation": f"https://pypi.org/project/{package_name}/",
                            "licenseConcluded": "NOASSERTION",
                            "licenseDeclared": "NOASSERTION",
                            "copyrightText": "NOASSERTION",
                            "supplier": "Organization: PyPI"
                        })
        except Exception as e:
            logger.warning(f"解析 setup.py 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_pipfile(self, file_path):
        """简化版 Pipfile 解析"""
        dependencies = []
        in_packages_section = False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    
                    if line == '[packages]':
                        in_packages_section = True
                        continue
                    elif line.startswith('[') and line.endswith(']'):
                        in_packages_section = False
                        continue
                    
                    if in_packages_section and '=' in line:
                        parts = line.split('=', 1)
                        package_name = parts[0].strip().strip('"\'')
                        version = parts[1].strip().strip('"\'')
                        
                        dependencies.append({
                            "name": package_name,
                            "SPDXID": f"SPDXRef-Package-{package_name}",
                            "versionInfo": version,
                            "downloadLocation": f"https://pypi.org/project/{package_name}/",
                            "licenseConcluded": "NOASSERTION",
                            "licenseDeclared": "NOASSERTION",
                            "copyrightText": "NOASSERTION",
                            "supplier": "Organization: PyPI"
                        })
        except Exception as e:
            logger.warning(f"解析 Pipfile 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_pyproject_toml(self, file_path):
        """简化版 pyproject.toml 解析"""
        dependencies = []
        
        try:
            # 使用 toml 库解析
            if toml:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = toml.load(f)
                    
                    # 处理 poetry 依赖
                    if 'tool' in data and 'poetry' in data['tool'] and 'dependencies' in data['tool']['poetry']:
                        for name, version_info in data['tool']['poetry']['dependencies'].items():
                            if name == 'python':  # 跳过 python 解释器版本
                                continue
                                
                            # 处理不同格式的版本信息
                            if isinstance(version_info, str):
                                version = version_info
                            elif isinstance(version_info, dict) and 'version' in version_info:
                                version = version_info['version']
                            else:
                                version = "NOASSERTION"
                            
                            dependencies.append({
                                "name": name,
                                "SPDXID": f"SPDXRef-Package-{name}",
                                "versionInfo": version,
                                "downloadLocation": f"https://pypi.org/project/{name}/",
                                "licenseConcluded": "NOASSERTION",
                                "licenseDeclared": "NOASSERTION",
                                "copyrightText": "NOASSERTION",
                                "supplier": "Organization: PyPI"
                            })
                    
                    # 处理 PEP 621 项目依赖
                    if 'project' in data and 'dependencies' in data['project']:
                        for dep in data['project']['dependencies']:
                            # 处理 PEP 508 格式的依赖说明
                            parts = re.split(r'[<>=~]', dep, 1)
                            package_name = parts[0].strip()
                            
                            if len(parts) > 1:
                                version = dep[len(package_name):].strip()
                            else:
                                version = "NOASSERTION"
                                
                            dependencies.append({
                                "name": package_name,
                                "SPDXID": f"SPDXRef-Package-{package_name}",
                                "versionInfo": version,
                                "downloadLocation": f"https://pypi.org/project/{package_name}/",
                                "licenseConcluded": "NOASSERTION",
                                "licenseDeclared": "NOASSERTION",
                                "copyrightText": "NOASSERTION",
                                "supplier": "Organization: PyPI"
                            })
                    
                    return dependencies
                except Exception as e:
                    logger.warning(f"使用 toml 库解析 {file_path} 时出错: {e}，将尝试简单解析方式")
            else:
                logger.warning("未安装 toml 库，将使用简单方式解析 pyproject.toml 文件")
            
            # 简单的行解析方式（作为备选方案）
            in_dependencies_section = False
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    
                    if line == '[tool.poetry.dependencies]' or line == '[project.dependencies]':
                        in_dependencies_section = True
                        continue
                    elif line.startswith('[') and line.endswith(']'):
                        in_dependencies_section = False
                        continue
                    
                    if in_dependencies_section and '=' in line:
                        parts = line.split('=', 1)
                        package_name = parts[0].strip().strip('"\'')
                        
                        if package_name == 'python':  # 跳过 python 解释器版本
                            continue
                            
                        version = parts[1].strip().strip('"\'')
                        
                        dependencies.append({
                            "name": package_name,
                            "SPDXID": f"SPDXRef-Package-{package_name}",
                            "versionInfo": version,
                            "downloadLocation": f"https://pypi.org/project/{package_name}/",
                            "licenseConcluded": "NOASSERTION",
                            "licenseDeclared": "NOASSERTION",
                            "copyrightText": "NOASSERTION",
                            "supplier": "Organization: PyPI"
                        })
                        
        except Exception as e:
            logger.warning(f"解析 pyproject.toml 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_pom_xml(self, file_path):
        """解析 Maven POM 文件（简化版本）"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            if not content.strip():
                logger.warning(f"pom.xml 文件 {file_path} 为空")
                return dependencies
            
            # 规范化XML内容
            content = self._normalize_xml(content)
            
            # 先用正则表达式检查文件是否合法
            if not re.search(r'<project', content):
                logger.warning(f"pom.xml 文件 {file_path} 不包含 project 元素")
                return dependencies
            
            # 查找所有 dependency 元素，支持不同的格式
            # 1. <dependency>...</dependency> 格式
            for dep_match in re.finditer(r'<dependency[^>]*>(.*?)</dependency>', content, re.DOTALL):
                dep_content = dep_match.group(1)
                
                # 提取 groupId, artifactId 和 version
                group_id = re.search(r'<groupId[^>]*>(.*?)</groupId>', dep_content)
                artifact_id = re.search(r'<artifactId[^>]*>(.*?)</artifactId>', dep_content)
                version = re.search(r'<version[^>]*>(.*?)</version>', dep_content)
                
                if group_id and artifact_id:
                    group_id = group_id.group(1).strip()
                    artifact_id = artifact_id.group(1).strip()
                    version_str = version.group(1).strip() if version else "NOASSERTION"
                    
                    package_name = f"{group_id}:{artifact_id}"
                    
                    dependencies.append({
                        "name": package_name,
                        "SPDXID": f"SPDXRef-Package-{hashlib.md5(package_name.encode()).hexdigest()}",
                        "versionInfo": version_str,
                        "downloadLocation": f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}",
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                        "supplier": "Organization: Maven Central"
                    })
        except Exception as e:
            logger.warning(f"解析 pom.xml 文件 {file_path} 时出错: {e}")
        
        return dependencies

    def _normalize_xml(self, content):
        """
        规范化 XML 内容
        
        Args:
            content (str): XML 内容
            
        Returns:
            str: 规范化后的 XML 内容
        """
        # 移除XML注释
        content = re.sub(r'<!--[\s\S]*?-->', '', content)
        
        # 规范化空白字符 - 减少多个连续空格/换行为单个空格
        content = re.sub(r'\s+', ' ', content)
        
        # 恢复XML标签格式 - 在尖括号后添加适当的空格
        content = re.sub(r'<\s+', '<', content)
        content = re.sub(r'\s+>', '>', content)
        
        # 恢复结束标签 - 确保结束标签格式正确
        content = re.sub(r'<\s*/\s*', '</', content)
        
        return content
    
    def _parse_gradle(self, file_path):
        """解析 Gradle 构建文件（简化版本）"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 规范化Gradle构建文件内容
            content = self._normalize_gradle(content)
            
            # 查找依赖项声明
            # 支持多种常见的依赖声明格式:
            # 1. implementation 'group:name:version'
            # 2. api "group:name:version"
            # 3. implementation(group: 'org.example', name: 'lib', version: '1.0')
            # 4. implementation group: 'org.example', name: 'lib', version: '1.0'
            
            # 处理单引号或双引号包围的简单格式
            for match in re.finditer(r'(implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[\'\"]([^\'"]+)[\'"]', content):
                dep_str = match.group(2)
                
                # 尝试解析 'group:name:version' 格式
                parts = dep_str.split(':')
                if len(parts) >= 2:
                    group_id = parts[0]
                    artifact_id = parts[1]
                    version = parts[2] if len(parts) > 2 else "NOASSERTION"
                    
                    package_name = f"{group_id}:{artifact_id}"
                    
                    dependencies.append({
                        "name": package_name,
                        "SPDXID": f"SPDXRef-Package-{hashlib.md5(package_name.encode()).hexdigest()}",
                        "versionInfo": version,
                        "downloadLocation": f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}",
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                        "supplier": "Organization: Maven Central"
                    })
            
            # 处理 Map 形式声明 (处理括号和不带括号的两种情况)
            map_patterns = [
                # 带括号版本: implementation(group: 'org.example', name: 'lib', version: '1.0')
                r'(implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(\s*group\s*:\s*[\'"]([^\'"]+)[\'"]\s*,\s*name\s*:\s*[\'"]([^\'"]+)[\'"]\s*(?:,\s*version\s*:\s*[\'"]([^\'"]+)[\'"]\s*)?',
                # 不带括号版本: implementation group: 'org.example', name: 'lib', version: '1.0'
                r'(implementation|api|compileOnly|runtimeOnly|testImplementation)\s+group\s*:\s*[\'"]([^\'"]+)[\'"]\s*,\s*name\s*:\s*[\'"]([^\'"]+)[\'"]\s*(?:,\s*version\s*:\s*[\'"]([^\'"]+)[\'"]\s*)?'
            ]
            
            for pattern in map_patterns:
                for match in re.finditer(pattern, content):
                    group_id = match.group(2)
                    artifact_id = match.group(3)
                    version = match.group(4) if match.group(4) else "NOASSERTION"
                    
                    package_name = f"{group_id}:{artifact_id}"
                    
                    dependencies.append({
                        "name": package_name,
                        "SPDXID": f"SPDXRef-Package-{hashlib.md5(package_name.encode()).hexdigest()}",
                        "versionInfo": version,
                        "downloadLocation": f"https://mvnrepository.com/artifact/{group_id}/{artifact_id}",
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                        "supplier": "Organization: Maven Central"
                    })
                    
        except Exception as e:
            logger.warning(f"解析 Gradle 文件 {file_path} 时出错: {e}")
        
        return dependencies
        
    def _normalize_gradle(self, content):
        """
        规范化 Gradle 构建文件内容
        
        Args:
            content (str): Gradle 文件内容
            
        Returns:
            str: 规范化后的内容
        """
        # 移除单行注释
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        
        # 移除多行注释
        content = re.sub(r'/\*[\s\S]*?\*/', '', content)
        
        # 规范化字符串文字内部的空白
        # 将多行字符串变为单行以便更好地匹配
        def replace_multiline_string(match):
            s = match.group(1)
            s = re.sub(r'\s+', ' ', s)
            return f"'''{s}'''"
        
        # 处理三单引号字符串
        content = re.sub(r"'''([\s\S]+?)'''", replace_multiline_string, content)
        
        # 处理三双引号字符串
        content = re.sub(r'"""([\s\S]+?)"""', lambda m: '"""' + re.sub(r'\s+', ' ', m.group(1)) + '"""', content)
        
        # 格式化"implementation("等后面的内容，使它们在一行内
        # 这有助于正则表达式匹配
        def format_dependency_statement(match):
            stmt = match.group(1)
            content = match.group(2)
            # 移除内容中的换行和多余空格
            content = re.sub(r'\s+', ' ', content)
            return f"{stmt}({content})"
        
        content = re.sub(r'(implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(([\s\S]*?)\)', 
                        format_dependency_statement, content)
        
        return content
    
    def _write_sbom(self, sbom_document, output_file):
        """写入 SBOM 到文件"""
        # 确保输出目录存在
        output_dir = os.path.dirname(os.path.abspath(output_file))
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # 写入 SBOM 到文件
        if self.output_format.lower() == "json":
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(sbom_document, f, indent=2, ensure_ascii=False)
        else:
            # Tag-value 格式
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"SPDXVersion: {sbom_document['spdxVersion']}\n")
                f.write(f"DataLicense: {sbom_document['dataLicense']}\n")
                f.write(f"SPDXID: {sbom_document['SPDXID']}\n")
                f.write(f"DocumentName: {sbom_document['name']}\n")
                f.write(f"DocumentNamespace: {sbom_document['documentNamespace']}\n")
                f.write(f"Creator: {sbom_document['creationInfo']['creators'][0]}\n")
                f.write(f"Creator: {sbom_document['creationInfo']['creators'][1]}\n")
                f.write(f"Created: {sbom_document['creationInfo']['created']}\n")
                f.write(f"LicenseListVersion: {sbom_document['creationInfo']['licenseListVersion']}\n")
                # 更多 tag-value 对将在真实实现中写入 