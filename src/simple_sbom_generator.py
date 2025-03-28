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
import requests
import concurrent.futures
from typing import Dict, List, Optional
from src.utils import (
    clean_temp_directory, 
    create_repo_temp_dir, 
    detect_programming_languages,
    get_package_manager_files,
    ensure_temp_directory,
    get_timestamp
)
import traceback

logger = logging.getLogger(__name__)

def import_helper(module_name):
    """尝试导入可选模块，如果不存在则返回 None"""
    try:
        return __import__(module_name)
    except ImportError:
        return None

# 导入可选的依赖解析模块
toml = import_helper('toml')

class PyPIClient:
    """PyPI API 客户端"""
    
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://pypi.org/pypi"
    
    def get_package_info(self, package_name: str) -> Optional[Dict]:
        """
        从 PyPI 获取包信息
        
        Args:
            package_name (str): 包名
            
        Returns:
            Optional[Dict]: 包信息字典，如果获取失败则返回 None
        """
        try:
            response = self.session.get(f"{self.base_url}/{package_name}/json")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.warning(f"获取包 {package_name} 的 PyPI 信息时出错: {e}")
            return None

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
        self.pypi_client = PyPIClient()
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
    
    def generate_sbom_from_local_path(self, local_path, output_file, project_name=None):
        """
        为本地项目目录生成 SBOM
        
        Args:
            local_path (str): 本地项目目录路径
            output_file (str): 输出文件路径
            project_name (str, optional): 项目名称，如果不提供则使用目录名
            
        Returns:
            str: 生成的 SBOM 文件路径
        """
        try:
            # 检查本地路径是否存在
            if not os.path.exists(local_path):
                raise ValueError(f"指定的本地路径不存在: {local_path}")
                
            if not os.path.isdir(local_path):
                raise ValueError(f"指定的路径不是一个目录: {local_path}")
            
            # 获取项目名称
            if not project_name:
                project_name = os.path.basename(os.path.normpath(local_path))
            
            logger.info(f"开始为本地项目 {project_name} 生成SBOM")
            
            # 创建一个简单的元数据对象
            metadata = {
                "name": project_name,
                "description": f"Local project: {project_name}",
                "license": None,
                "clone_url": f"file://{os.path.abspath(local_path)}",
                "html_url": f"file://{os.path.abspath(local_path)}",
                "default_branch": "local"
            }
            
            # 创建 SBOM 文档
            sbom_document = self._create_sbom_document(
                "local", project_name, local_path, metadata
            )
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
            logger.error(f"从本地路径生成 SBOM 时出错: {e}", exc_info=True)
            raise
    
    def cleanup(self):
        """清理临时文件"""
        if self.repo_temp_dir and os.path.exists(self.repo_temp_dir):
            clean_temp_directory(self.repo_temp_dir)
            logger.info(f"清理临时目录: {self.repo_temp_dir}")
    
    def _enhance_python_packages(self, packages: List[Dict], max_workers: int = 10) -> List[Dict]:
        """
        通过 PyPI API 增强 Python 包的信息
        
        Args:
            packages (List[Dict]): 包列表
            max_workers (int): 最大线程数
            
        Returns:
            List[Dict]: 增强后的包列表
        """
        python_packages = [p for p in packages if p.get('supplier', '').startswith('Organization: PyPI')]
        if not python_packages:
            return packages
            
        logger.info(f"开始从 PyPI 获取 {len(python_packages)} 个包的信息...")
        
        def process_package(package: Dict) -> Dict:
            package_name = package['name']
            pypi_info = self.pypi_client.get_package_info(package_name)
            
            # 保存任何现有的注释
            original_comment = package.get('comment', '')
            
            if pypi_info and 'info' in pypi_info:
                info = pypi_info['info']
                
                # 更新许可证信息
                license_info = None
                
                # 1. 首先尝试从 classifiers 中获取许可证信息
                if 'classifiers' in info:
                    license_classifiers = [c for c in info['classifiers'] if c.startswith('License :: ')]
                    if license_classifiers:
                        # 获取最后一个许可证分类器（通常是最具体的）
                        license_info = license_classifiers[-1].replace('License :: OSI Approved :: ', '')
                
                # 2. 如果没有从 classifiers 获取到，或者主许可证字段过长，则使用主许可证字段
                if not license_info and 'license' in info:
                    license_info = info['license']
                    # 如果主许可证字段过长（超过100个字符），则使用 classifiers 中的信息
                    if license_info and len(license_info) > 100 and 'classifiers' in info:
                        license_classifiers = [c for c in info['classifiers'] if c.startswith('License :: ')]
                        if license_classifiers:
                            license_info = license_classifiers[-1].replace('License :: OSI Approved :: ', '')
                
                if license_info:
                    package['licenseDeclared'] = license_info
                    package['licenseConcluded'] = license_info
                
                # 更新版权信息
                if 'author' in info:
                    package['copyrightText'] = f"Copyright (c) {info['author']}"
                
                # 更新描述信息
                if 'summary' in info:
                    package['description'] = info['summary']
                
                # 更新主页
                if 'home_page' in info and info['home_page']:
                    package['homepage'] = info['home_page']
                
                # 更新下载位置
                if 'package_url' in info:
                    package['downloadLocation'] = info['package_url']
                
                # 更新供应商信息
                if 'author' in info and info['author'] and info['author'].lower() != 'none':
                    package['supplier'] = f"Person: {info['author']}"
                elif 'maintainer' in info and info['maintainer'] and info['maintainer'].lower() != 'none':
                    package['supplier'] = f"Person: {info['maintainer']}"
                else:
                    package['supplier'] = "Organization: PyPI"
                
                # 重新添加原始注释
                if original_comment:
                    if 'comment' in package:
                        package['comment'] = f"{package['comment']}; {original_comment}"
                    else:
                        package['comment'] = original_comment
            
            return package
        
        # 使用线程池并行处理
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            enhanced_packages = list(tqdm(
                executor.map(process_package, python_packages),
                total=len(python_packages),
                desc="获取 PyPI 信息"
            ))
        
        # 创建映射以更新原始包列表中的 Python 包信息
        enhanced_map = {}
        for pkg in enhanced_packages:
            # 使用包的SPDXID作为键，确保不会混淆同名但版本不同的包
            enhanced_map[pkg['SPDXID']] = pkg
        
        # 更新原始包列表
        for i, package in enumerate(packages):
            if package.get('supplier', '').startswith('Organization: PyPI') and package['SPDXID'] in enhanced_map:
                packages[i] = enhanced_map[package['SPDXID']]
        
        return packages

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
        
        # 使用复合键（包名+版本号+条件）去重
        dep_keys = set()
        
        # 保存每个源文件的依赖项信息，用于日志记录
        source_deps = {}
        
        if package_files:
            logger.info(f"发现 {len(package_files)} 个包管理器文件，开始解析依赖项...")
            
            for manager, file_path in package_files:
                abs_path = os.path.join(repo_dir, file_path)
                if os.path.exists(abs_path):
                    # 解析依赖项
                    extracted_deps = self._extract_dependencies(manager, abs_path)
                    source_deps[file_path] = len(extracted_deps)
                    
                    if extracted_deps:
                        # 使用精确的去重逻辑
                        added_from_file = 0
                        
                        for dep in extracted_deps:
                            dep_name = dep['name']
                            version_info = dep['versionInfo']
                            
                            # 创建唯一键: 包名+版本号
                            # 对于条件依赖，会将条件也包含在内，使不同条件的同名包被视为不同的依赖项
                            key = f"{dep_name}|{version_info}"
                            
                            if key not in dep_keys:
                                dependencies.append(dep)
                                dep_keys.add(key)
                                added_from_file += 1
                            else:
                                # 日志记录避免添加重复项
                                logger.debug(f"跳过重复的依赖项: {dep_name} 版本: {version_info}")
                        
                        logger.info(f"从 {file_path} 中提取了 {len(extracted_deps)} 个依赖项，添加了 {added_from_file} 个新依赖项")
                    else:
                        logger.info(f"从 {file_path} 中未提取到依赖项")
                else:
                    logger.warning(f"无法访问文件: {abs_path}")
        else:
            logger.info("未找到包管理器文件")
        
        # 打印每个文件发现的依赖项数量，帮助调试
        logger.info("每个包管理器文件中发现的依赖项数量:")
        for file_path, count in source_deps.items():
            logger.info(f"  - {file_path}: {count} 个依赖项")
        
        # 将依赖项添加到 packages 列表中
        for dep in dependencies:
            packages.append(dep)
        
        # 通过 PyPI API 增强 Python 包信息
        packages = self._enhance_python_packages(packages)
        
        logger.info(f"总共收集了 {len(packages)} 个包的信息 (包含 {len(dependencies)} 个依赖项)")
        
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
        file_basename = os.path.basename(file_path)
        
        try:
            if manager == 'Python':
                if file_path.endswith('requirements.txt') or 'requirements' in file_path.lower() and file_path.endswith('.txt'):
                    logger.info(f"使用requirements.txt解析器处理文件: {file_basename}")
                    dependencies.extend(self._parse_requirements_txt(file_path))
                elif file_path.endswith('setup.py'):
                    logger.info(f"使用setup.py解析器处理文件: {file_basename}")
                    dependencies.extend(self._parse_setup_py(file_path))
                elif file_path.endswith('Pipfile'):
                    logger.info(f"使用Pipfile解析器处理文件: {file_basename}")
                    dependencies.extend(self._parse_pipfile(file_path))
                elif file_path.endswith('pyproject.toml'):
                    logger.info(f"使用pyproject.toml解析器处理文件: {file_basename}")
                    dependencies.extend(self._parse_pyproject_toml(file_path))
            
            elif manager == 'JavaScript/Node.js':
                if file_path.endswith('package.json'):
                    logger.info(f"使用package.json解析器处理文件: {file_basename}")
                    dependencies.extend(self._parse_package_json(file_path))
                elif file_path.endswith('package-lock.json'):
                    logger.info(f"使用package-lock.json解析器处理文件: {file_basename}")
                    dependencies.extend(self._parse_package_lock_json(file_path))
                elif file_path.endswith('yarn.lock'):
                    logger.info(f"使用yarn.lock解析器处理文件: {file_basename}")
                    dependencies.extend(self._parse_yarn_lock(file_path))
            
            elif manager == 'Go':
                if file_path.endswith('go.mod'):
                    dependencies.extend(self._parse_go_mod(file_path))
            
            elif manager == 'Java':
                if file_path.endswith('pom.xml'):
                    dependencies.extend(self._parse_pom_xml(file_path))
                elif file_path.endswith('.gradle') or file_path.endswith('.gradle.kts'):
                    dependencies.extend(self._parse_gradle(file_path))
            
            elif manager == 'Ruby':
                if file_path.endswith('Gemfile') or file_path.endswith('Gemfile.lock'):
                    dependencies.extend(self._parse_gemfile(file_path))
                elif file_path.endswith('.gemspec'):
                    dependencies.extend(self._parse_gemspec(file_path))
            
            elif manager == 'PHP':
                if file_path.endswith('composer.json') or file_path.endswith('composer.lock'):
                    dependencies.extend(self._parse_composer_json(file_path))
            
            elif manager == 'Rust':
                if file_path.endswith('Cargo.toml') or file_path.endswith('Cargo.lock'):
                    dependencies.extend(self._parse_cargo_toml(file_path))
            
            elif manager == 'Dart/Flutter':
                if file_path.endswith('pubspec.yaml'):
                    dependencies.extend(self._parse_pubspec_yaml(file_path))
            
            # 可以根据需要添加更多的包管理器解析逻辑
            
            if dependencies:
                logger.info(f"从 {file_basename} 中提取了 {len(dependencies)} 个依赖项")
            else:
                # 如果未提取到依赖项，尝试使用通用的requirements.txt解析器
                if file_path.endswith('.txt') and manager == 'Python':
                    # 检查文件内容是否类似于 requirements.txt
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            # 检查是否包含常见的requirements.txt模式
                            if re.search(r'([a-zA-Z0-9._-]+)([<>=~!][<>=~!]?.*)', content) or \
                               re.search(r'^--index-url', content, re.MULTILINE) or \
                               re.search(r'^-r\s+', content, re.MULTILINE):
                                logger.info(f"尝试将 {file_basename} 作为 requirements.txt 进行解析")
                                dependencies.extend(self._parse_requirements_txt(file_path))
                                logger.info(f"通过备选方式从 {file_basename} 中提取了 {len(dependencies)} 个依赖项")
                    except Exception as e:
                        logger.warning(f"尝试备选解析方式时出错: {e}")
                
                # 尝试处理未识别的yarn.lock文件
                elif file_path.endswith('.lock') and 'yarn' in file_basename.lower():
                    logger.info(f"尝试以yarn.lock方式解析: {file_basename}")
                    try:
                        dependencies.extend(self._parse_yarn_lock(file_path))
                        logger.info(f"通过备选方式从 {file_basename} 中提取了 {len(dependencies)} 个依赖项")
                    except Exception as e:
                        logger.warning(f"尝试yarn.lock备选解析方式时出错: {e}")
            
        except Exception as e:
            logger.warning(f"解析依赖项文件 {file_path} 时出错: {e}")
            logger.debug(f"详细错误: {traceback.format_exc()}")
        
        return dependencies
    
    def _parse_requirements_txt(self, file_path):
        """解析 requirements.txt 文件"""
        dependencies = []
        processed_files = set()  # 用于跟踪已处理的文件，避免循环引用
        
        # 提取文件基本名用于日志显示
        file_basename = os.path.basename(file_path)
        logger.info(f"开始解析 {file_basename}")
        
        def parse_file(file_path, processed_files):
            """递归解析requirements文件及其引用的文件"""
            if file_path in processed_files:
                return []  # 避免循环引用
            
            processed_files.add(file_path)
            local_dependencies = []
            file_basename = os.path.basename(file_path)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                    # 跟踪前缀选项的状态，例如 --index-url
                    current_index_url = None
                    
                    for line_num, line in enumerate(lines, 1):
                        original_line = line
                        # 删除注释和空格
                        line = line.split('#')[0].strip()
                        if not line:
                            continue
                        
                        # 处理选项行
                        if line.startswith('--'):
                            # 记录 index-url 以便在日志中显示
                            if line.startswith('--index-url'):
                                parts = line.split('--index-url', 1)[1].strip()
                                current_index_url = parts
                                logger.info(f"检测到自定义索引URL: {current_index_url}")
                            continue
                        
                        # 处理文件引用 (-r file.txt 或 --requirement file.txt)
                        if line.startswith('-r ') or line.startswith('--requirement '):
                            referenced_file = line.split(' ', 1)[1].strip()
                            # 确定引用文件的路径
                            ref_path = os.path.join(os.path.dirname(file_path), referenced_file)
                            
                            # 尝试多种路径可能性
                            if not os.path.exists(ref_path):
                                # 尝试通用名称匹配
                                alt_refs = [
                                    ref_path,  # 原始路径
                                    os.path.abspath(referenced_file),  # 绝对路径
                                    referenced_file,  # 仅文件名
                                    os.path.join(os.getcwd(), referenced_file)  # 当前工作目录
                                ]
                                
                                # 查找匹配的文件
                                for alt_ref in alt_refs:
                                    if os.path.exists(alt_ref):
                                        ref_path = alt_ref
                                        break
                            
                            if os.path.exists(ref_path):
                                logger.info(f"处理引用的文件: {referenced_file}")
                                # 递归解析引用的文件
                                ref_deps = parse_file(ref_path, processed_files)
                                local_dependencies.extend(ref_deps)
                                logger.info(f"从 {referenced_file} 中解析了 {len(ref_deps)} 个依赖项")
                            else:
                                logger.warning(f"引用的文件不存在: {referenced_file} (从 {file_basename} 行 {line_num})")
                            continue
                        
                        # 跳过其他选项行，但打印日志以便调试
                        if line.startswith('-'):
                            logger.debug(f"跳过选项行: {line}")
                            continue
                        
                        # 处理条件性依赖 (包名==版本; 条件)
                        # 特殊处理引号内的分号，避免错误拆分
                        condition = None
                        
                        # 查找所有不在引号内的分号
                        semicolons = []
                        in_single_quote = False
                        in_double_quote = False
                        
                        for i, char in enumerate(line):
                            if char == "'" and (i == 0 or line[i-1] != '\\'):
                                in_single_quote = not in_single_quote
                            elif char == '"' and (i == 0 or line[i-1] != '\\'):
                                in_double_quote = not in_double_quote
                            elif char == ';' and not in_single_quote and not in_double_quote:
                                semicolons.append(i)
                        
                        if semicolons:
                            # 取第一个不在引号内的分号作为分隔
                            pkg_spec = line[:semicolons[0]].strip()
                            condition = line[semicolons[0]+1:].strip()
                        else:
                            pkg_spec = line
                        
                        # 处理egg格式，例如：package @ git+https://....git#egg=package
                        if '@' in pkg_spec and '#egg=' in pkg_spec.lower():
                            egg_part = pkg_spec.split('#egg=', 1)[1]
                            if egg_part:
                                package_name = egg_part.strip().split('[')[0].strip()
                                version = "from git"
                                pkg_source = pkg_spec.split('@', 1)[1].strip()
                                
                                # 创建唯一ID
                                unique_id = hashlib.md5(f"{package_name}|{version}|{condition}".encode()).hexdigest()
                                
                                local_dependencies.append({
                                    "name": package_name,
                                    "SPDXID": f"SPDXRef-Package-{unique_id}",
                                    "versionInfo": version + (f" ; {condition}" if condition else ""),
                                    "downloadLocation": pkg_source,
                                    "licenseConcluded": "NOASSERTION",
                                    "licenseDeclared": "NOASSERTION",
                                    "copyrightText": "NOASSERTION",
                                    "supplier": "Organization: PyPI",
                                    "comment": f"From {file_basename}" + (f" (via {current_index_url})" if current_index_url else "")
                                })
                                continue
                        
                        # 处理包名和版本
                        # 检查是否有版本操作符（考虑引号情况）
                        version_match = None
                        in_single_quote = False
                        in_double_quote = False
                        
                        for i, char in enumerate(pkg_spec):
                            if char == "'" and (i == 0 or pkg_spec[i-1] != '\\'):
                                in_single_quote = not in_single_quote
                            elif char == '"' and (i == 0 or pkg_spec[i-1] != '\\'):
                                in_double_quote = not in_double_quote
                            # 只在不在引号内时匹配版本操作符
                            elif not in_single_quote and not in_double_quote:
                                # 查找版本操作符
                                if char in '<>=~!':
                                    # 确认这是一个版本操作符
                                    if (i+1 < len(pkg_spec) and pkg_spec[i+1] in '=<>') or char == '~':
                                        version_match = i
                                        break
                                    elif char in '<>=!':
                                        version_match = i
                                        break
                        
                        if version_match is not None:
                            package_name = pkg_spec[:version_match].strip()
                            version = pkg_spec[version_match:].strip()
                        else:
                            # 检查是否有引号包裹的包名
                            if (pkg_spec.startswith('"') and pkg_spec.endswith('"')) or \
                               (pkg_spec.startswith("'") and pkg_spec.endswith("'")):
                                package_name = pkg_spec[1:-1].strip()
                            else:
                                package_name = pkg_spec.strip()
                            version = "NOASSERTION"
                        
                        # 处理包名中的引号
                        if (package_name.startswith('"') and package_name.endswith('"')) or \
                           (package_name.startswith("'") and package_name.endswith("'")):
                            package_name = package_name[1:-1]
                        
                        # 移除包名中的空格
                        package_name = package_name.strip()
                        
                        # 跳过空包名（可能是由于格式错误导致）
                        if not package_name:
                            logger.warning(f"跳过空包名: {original_line}")
                            continue
                            
                        # 处理包名中的可选部分，如 package[extra]
                        base_package_name = package_name
                        extras = None
                        if '[' in package_name and package_name.endswith(']'):
                            base_package_name = package_name.split('[')[0]
                            extras = package_name.split('[')[1][:-1]
                        
                        # 如果有条件，将条件添加到版本信息中
                        if condition:
                            # 清理条件中的多余引号
                            condition = condition.strip()
                            version_with_condition = f"{version} ; {condition}" if version != "NOASSERTION" else f"NOASSERTION ; {condition}"
                        else:
                            version_with_condition = version
                        
                        # 创建一个唯一ID，包含包名、版本和条件
                        unique_id = hashlib.md5(f"{base_package_name}|{version_with_condition}".encode()).hexdigest()
                        
                        local_dependencies.append({
                            "name": base_package_name,
                            "SPDXID": f"SPDXRef-Package-{unique_id}",
                            "versionInfo": version_with_condition,
                            "downloadLocation": f"https://pypi.org/project/{base_package_name}/",
                            "licenseConcluded": "NOASSERTION",
                            "licenseDeclared": "NOASSERTION",
                            "copyrightText": "NOASSERTION",
                            "supplier": "Organization: PyPI",
                            "comment": f"From {file_basename}" + 
                                      (f", extras: {extras}" if extras else "") + 
                                      (f" (via {current_index_url})" if current_index_url else "")
                        })
            except Exception as e:
                logger.warning(f"解析 requirements 文件 {file_path} 时出错: {e}")
                # 打印更详细的错误信息进行调试
                logger.debug(f"详细错误: {traceback.format_exc()}")
            
            return local_dependencies
        
        # 开始解析主文件
        dependencies = parse_file(file_path, processed_files)
        logger.info(f"从 {file_basename} 及其引用文件中共解析了 {len(dependencies)} 个依赖项")
        return dependencies
    
    def _parse_package_json(self, file_path):
        """解析 package.json 文件"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                data = json.loads(content)
                # 获取主包的许可证信息
                license_info = data.get('license', {})
                if isinstance(license_info, str):
                    license_declared = license_info
                elif isinstance(license_info, dict):
                    license_declared = license_info.get('type', 'NOASSERTION')
                else:
                    license_declared = 'NOASSERTION'
                
                # 获取版权信息
                copyright_text = data.get('copyright', 'NOASSERTION')
                
                # 获取作者信息
                author_info = data.get('author', {})
                if isinstance(author_info, str):
                    supplier = f"Person: {author_info}"
                elif isinstance(author_info, dict):
                    supplier = f"Person: {author_info.get('name', 'NOASSERTION')}"
                else:
                    supplier = "Organization: npm"
                
                # 解析依赖项
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
                                "licenseConcluded": license_declared,
                                "licenseDeclared": license_declared,
                                "copyrightText": copyright_text,
                                "supplier": supplier
                            })
        except Exception as e:
            logger.warning(f"解析 package.json 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_go_mod(self, file_path):
        """解析 go.mod 文件"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # 获取模块信息
                module_match = re.search(r'module\s+([^\s]+)', content)
                if module_match:
                    module_name = module_match.group(1)
                    
                    # 尝试从 LICENSE 文件获取许可证信息
                    license_file = os.path.join(os.path.dirname(file_path), 'LICENSE')
                    license_declared = 'NOASSERTION'
                    copyright_text = 'NOASSERTION'
                    
                    if os.path.exists(license_file):
                        try:
                            with open(license_file, 'r', encoding='utf-8') as lf:
                                license_content = lf.read()
                                # 尝试从许可证文件内容中提取版权信息
                                copyright_match = re.search(r'Copyright\s+\([cC]\)\s+(\d{4}(-\d{4})?\s+[^\.]+)', license_content)
                                if copyright_match:
                                    copyright_text = copyright_match.group(1)
                                
                                # 尝试识别许可证类型
                                if 'MIT License' in license_content:
                                    license_declared = 'MIT'
                                elif 'Apache License' in license_content:
                                    license_declared = 'Apache-2.0'
                                elif 'GNU General Public License' in license_content:
                                    license_declared = 'GPL-3.0-or-later'
                        except Exception as e:
                            logger.warning(f"读取 LICENSE 文件时出错: {e}")
                    
                    # 解析 require 语句
                    require_blocks = re.finditer(r'require\s*\(([\s\S]*?)\)', content)
                    for block in require_blocks:
                        block_content = block.group(1)
                        # 处理多行 require 块
                        for line in block_content.split('\n'):
                            line = line.strip()
                            if not line or line.startswith('//'):
                                continue
                            req_match = re.match(r'([^\s]+)\s+([^\s]+)', line)
                            if req_match:
                                name = req_match.group(1)
                                version = req_match.group(2)
                                
                                dependencies.append({
                                    "name": name,
                                    "SPDXID": f"SPDXRef-Package-{hashlib.md5(name.encode()).hexdigest()}",
                                    "versionInfo": version,
                                    "downloadLocation": f"https://pkg.go.dev/{name}",
                                    "licenseConcluded": license_declared,
                                    "licenseDeclared": license_declared,
                                    "copyrightText": copyright_text,
                                    "supplier": f"Organization: {module_name.split('/')[0]}"
                                })
                    
                    # 解析单行 require 语句
                    single_requires = re.finditer(r'require\s+([^\s]+)\s+([^\s]+)', content)
                    for req in single_requires:
                        name = req.group(1)
                        version = req.group(2)
                        
                        dependencies.append({
                            "name": name,
                            "SPDXID": f"SPDXRef-Package-{hashlib.md5(name.encode()).hexdigest()}",
                            "versionInfo": version,
                            "downloadLocation": f"https://pkg.go.dev/{name}",
                            "licenseConcluded": license_declared,
                            "licenseDeclared": license_declared,
                            "copyrightText": copyright_text,
                            "supplier": f"Organization: {module_name.split('/')[0]}"
                        })
        except Exception as e:
            logger.warning(f"解析 go.mod 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_setup_py(self, file_path):
        """解析 setup.py 文件（简化版本）"""
        dependencies = []
        file_basename = os.path.basename(file_path)
        logger.info(f"开始解析 {file_basename}")
        
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
                        parts = re.split(r'([<>=~!]+)', req, 1)
                        package_name = parts[0].strip()
                        
                        if len(parts) > 1:
                            version = ''.join(parts[1:]).strip()
                        else:
                            version = "NOASSERTION"
                        
                        # 跳过空包名
                        if not package_name:
                            continue
                            
                        # 处理可能的条件依赖
                        condition = None
                        if ';' in version:
                            version_parts = version.split(';', 1)
                            version = version_parts[0].strip()
                            condition = version_parts[1].strip()
                            
                        # 如果有条件，将条件添加到版本信息中
                        if condition:
                            version_with_condition = f"{version} ; {condition}" if version != "NOASSERTION" else f"NOASSERTION ; {condition}"
                        else:
                            version_with_condition = version
                            
                        # 创建唯一ID
                        unique_id = hashlib.md5(f"{package_name}|{version_with_condition}".encode()).hexdigest()
                        
                        dependencies.append({
                            "name": package_name,
                            "SPDXID": f"SPDXRef-Package-{unique_id}",
                            "versionInfo": version_with_condition,
                            "downloadLocation": f"https://pypi.org/project/{package_name}/",
                            "licenseConcluded": "NOASSERTION",
                            "licenseDeclared": "NOASSERTION",
                            "copyrightText": "NOASSERTION",
                            "supplier": "Organization: PyPI",
                            "comment": f"From {file_basename} (install_requires)"
                        })
                
                # 查找 extras_require 字典
                extras_match = re.search(r'extras_require\s*=\s*{(.*?)}', content, re.DOTALL)
                if extras_match:
                    extras_str = extras_match.group(1)
                    
                    # 提取每个额外依赖组
                    extras_sections = re.finditer(r'[\'"]([^\'"]+)[\'"]\s*:\s*\[(.*?)\]', extras_str, re.DOTALL)
                    for section in extras_sections:
                        extra_name = section.group(1)
                        extra_deps = section.group(2)
                        
                        # 提取每个依赖项
                        for dep in re.finditer(r'[\'"]([^\'"]+)[\'"]', extra_deps):
                            req = dep.group(1).strip()
                            
                            # 处理包名和版本
                            parts = re.split(r'([<>=~!]+)', req, 1)
                            package_name = parts[0].strip()
                            
                            if len(parts) > 1:
                                version = ''.join(parts[1:]).strip()
                            else:
                                version = "NOASSERTION"
                            
                            # 处理可能的条件依赖
                            condition = None
                            if ';' in version:
                                version_parts = version.split(';', 1)
                                version = version_parts[0].strip()
                                condition = version_parts[1].strip()
                                
                            # 如果有条件，将条件添加到版本信息中
                            if condition:
                                version_with_condition = f"{version} ; {condition}" if version != "NOASSERTION" else f"NOASSERTION ; {condition}"
                            else:
                                version_with_condition = version
                                
                            # 创建唯一ID，包含额外依赖组信息
                            unique_id = hashlib.md5(f"{package_name}|{version_with_condition}|{extra_name}".encode()).hexdigest()
                            
                            dependencies.append({
                                "name": package_name,
                                "SPDXID": f"SPDXRef-Package-{unique_id}",
                                "versionInfo": version_with_condition,
                                "downloadLocation": f"https://pypi.org/project/{package_name}/",
                                "licenseConcluded": "NOASSERTION",
                                "licenseDeclared": "NOASSERTION",
                                "copyrightText": "NOASSERTION",
                                "supplier": "Organization: PyPI",
                                "comment": f"From {file_basename} (extras_require.{extra_name})"
                            })
                
                logger.info(f"从 {file_basename} 中解析了 {len(dependencies)} 个依赖项")
                
        except Exception as e:
            logger.warning(f"解析 setup.py 文件 {file_path} 时出错: {e}")
            logger.debug(f"详细错误: {traceback.format_exc()}")
        
        return dependencies
    
    def _parse_pipfile(self, file_path):
        """简化版 Pipfile 解析"""
        dependencies = []
        file_basename = os.path.basename(file_path)
        logger.info(f"开始解析 {file_basename}")
        
        try:
            current_section = None
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    
                    # 跳过空行和注释
                    if not line or line.startswith('#'):
                        continue
                    
                    # 处理段落标签
                    if line.startswith('[') and line.endswith(']'):
                        current_section = line[1:-1].lower()
                        logger.debug(f"处理 Pipfile 段落: {current_section}")
                        continue
                    
                    # 只处理packages和dev-packages段落
                    if current_section in ['packages', 'dev-packages'] and '=' in line:
                        parts = line.split('=', 1)
                        package_name = parts[0].strip().strip('"\'')
                        version_raw = parts[1].strip()
                        
                        # 处理版本格式 (可能包含引号、花括号等)
                        if version_raw.startswith('{') and version_raw.endswith('}'):
                            # 复杂版本说明，如 {version=">=1.0.0", extras=["full"]}
                            version_dict = {}
                            version_parts = version_raw[1:-1].split(',')
                            for part in version_parts:
                                if '=' in part:
                                    k, v = part.split('=', 1)
                                    version_dict[k.strip()] = v.strip().strip('"\'')
                            
                            version = version_dict.get('version', 'NOASSERTION')
                            extras = version_dict.get('extras', None)
                            extras_str = f", extras: {extras}" if extras else ""
                        else:
                            # 简单版本，如 ">=1.0.0"
                            version = version_raw.strip('"\'')
                            extras_str = ""
                        
                        # 创建唯一ID
                        unique_id = hashlib.md5(f"{package_name}|{version}|{current_section}".encode()).hexdigest()
                        
                        dependencies.append({
                            "name": package_name,
                            "SPDXID": f"SPDXRef-Package-{unique_id}",
                            "versionInfo": version,
                            "downloadLocation": f"https://pypi.org/project/{package_name}/",
                            "licenseConcluded": "NOASSERTION",
                            "licenseDeclared": "NOASSERTION",
                            "copyrightText": "NOASSERTION",
                            "supplier": "Organization: PyPI",
                            "comment": f"From {file_basename} ({current_section}){extras_str}"
                        })
            
            logger.info(f"从 {file_basename} 中解析了 {len(dependencies)} 个依赖项")
            
        except Exception as e:
            logger.warning(f"解析 Pipfile 文件 {file_path} 时出错: {e}")
            logger.debug(f"详细错误: {traceback.format_exc()}")
        
        return dependencies
    
    def _parse_pyproject_toml(self, file_path):
        """简化版 pyproject.toml 解析"""
        dependencies = []
        file_basename = os.path.basename(file_path)
        logger.info(f"解析 {file_basename}")
        
        try:
            # 使用 toml 库解析
            if toml:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = toml.load(f)
                    
                    # 处理 PEP 621 格式 (project.dependencies)
                    if 'project' in data and 'dependencies' in data['project']:
                        project_deps = data['project']['dependencies']
                        if isinstance(project_deps, list):
                            for dep in project_deps:
                                # 分离条件依赖
                                pkg_spec = dep
                                condition = None
                                
                                # 查找不在引号内的分号
                                semicolons = []
                                in_single_quote = False
                                in_double_quote = False
                                
                                for i, char in enumerate(pkg_spec):
                                    if char == "'" and (i == 0 or pkg_spec[i-1] != '\\'):
                                        in_single_quote = not in_single_quote
                                    elif char == '"' and (i == 0 or pkg_spec[i-1] != '\\'):
                                        in_double_quote = not in_double_quote
                                    elif char == ';' and not in_single_quote and not in_double_quote:
                                        semicolons.append(i)
                                
                                if semicolons:
                                    # 取第一个不在引号内的分号作为分隔
                                    pkg_spec = dep[:semicolons[0]].strip()
                                    condition = dep[semicolons[0]+1:].strip()
                                
                                # 处理包名和版本
                                match = re.search(r'([a-zA-Z0-9._-]+)([<>=~!][<>=~!]?.*)', pkg_spec)
                                if match:
                                    package_name = match.group(1).strip()
                                    version = match.group(2).strip()
                                else:
                                    package_name = pkg_spec.strip()
                                    version = "NOASSERTION"
                                
                                # 如果有条件，将条件添加到版本信息中
                                if condition:
                                    version_with_condition = f"{version} ; {condition}" if version != "NOASSERTION" else f"NOASSERTION ; {condition}"
                                else:
                                    version_with_condition = version
                                
                                # 创建唯一ID
                                unique_id = hashlib.md5(f"{package_name}|{version_with_condition}".encode()).hexdigest()
                                
                                dependencies.append({
                                    "name": package_name,
                                    "SPDXID": f"SPDXRef-Package-{unique_id}",
                                    "versionInfo": version_with_condition,
                                    "downloadLocation": f"https://pypi.org/project/{package_name}/",
                                    "licenseConcluded": "NOASSERTION",
                                    "licenseDeclared": "NOASSERTION",
                                    "copyrightText": "NOASSERTION",
                                    "supplier": "Organization: PyPI",
                                    "comment": f"From {file_basename} (project.dependencies)"
                                })
                        elif isinstance(project_deps, dict):
                            # 处理字典形式的依赖声明
                            for name, version_info in project_deps.items():
                                if name == 'python':  # 跳过 python 解释器版本
                                    continue
                                    
                                # 处理不同格式的版本信息
                                if isinstance(version_info, str):
                                    version = version_info
                                elif isinstance(version_info, dict) and 'version' in version_info:
                                    version = version_info['version']
                                else:
                                    version = "NOASSERTION"
                                
                                # 创建唯一ID
                                unique_id = hashlib.md5(f"{name}|{version}".encode()).hexdigest()
                                
                                dependencies.append({
                                    "name": name,
                                    "SPDXID": f"SPDXRef-Package-{unique_id}",
                                    "versionInfo": version,
                                    "downloadLocation": f"https://pypi.org/project/{name}/",
                                    "licenseConcluded": "NOASSERTION",
                                    "licenseDeclared": "NOASSERTION",
                                    "copyrightText": "NOASSERTION",
                                    "supplier": "Organization: PyPI",
                                    "comment": f"From {file_basename} (project.dependencies)"
                                })
                    
                    # 处理 poetry 依赖
                    if 'tool' in data and 'poetry' in data['tool']:
                        if 'dependencies' in data['tool']['poetry']:
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
                                
                                # 创建唯一ID
                                unique_id = hashlib.md5(f"{name}|{version}".encode()).hexdigest()
                                
                                dependencies.append({
                                    "name": name,
                                    "SPDXID": f"SPDXRef-Package-{unique_id}",
                                    "versionInfo": version,
                                    "downloadLocation": f"https://pypi.org/project/{name}/",
                                    "licenseConcluded": "NOASSERTION",
                                    "licenseDeclared": "NOASSERTION",
                                    "copyrightText": "NOASSERTION",
                                    "supplier": "Organization: PyPI",
                                    "comment": f"From {file_basename} (poetry.dependencies)"
                                })
                        
                        # 处理开发依赖
                        if 'dev-dependencies' in data['tool']['poetry']:
                            for name, version_info in data['tool']['poetry']['dev-dependencies'].items():
                                # 处理不同格式的版本信息
                                if isinstance(version_info, str):
                                    version = version_info
                                elif isinstance(version_info, dict) and 'version' in version_info:
                                    version = version_info['version']
                                else:
                                    version = "NOASSERTION"
                                
                                # 创建唯一ID
                                unique_id = hashlib.md5(f"{name}|{version}".encode()).hexdigest()
                                
                                dependencies.append({
                                    "name": name,
                                    "SPDXID": f"SPDXRef-Package-{unique_id}",
                                    "versionInfo": version,
                                    "downloadLocation": f"https://pypi.org/project/{name}/",
                                    "licenseConcluded": "NOASSERTION",
                                    "licenseDeclared": "NOASSERTION",
                                    "copyrightText": "NOASSERTION",
                                    "supplier": "Organization: PyPI",
                                    "comment": f"From {file_basename} (poetry.dev-dependencies)"
                                })
                    
                    # 处理 optional-dependencies
                    if 'project' in data and 'optional-dependencies' in data['project']:
                        for group_name, deps in data['project']['optional-dependencies'].items():
                            if isinstance(deps, list):
                                for dep in deps:
                                    # 分离条件依赖
                                    pkg_spec = dep
                                    condition = None
                                    
                                    # 查找不在引号内的分号
                                    semicolons = []
                                    in_single_quote = False
                                    in_double_quote = False
                                    
                                    for i, char in enumerate(pkg_spec):
                                        if char == "'" and (i == 0 or pkg_spec[i-1] != '\\'):
                                            in_single_quote = not in_single_quote
                                        elif char == '"' and (i == 0 or pkg_spec[i-1] != '\\'):
                                            in_double_quote = not in_double_quote
                                        elif char == ';' and not in_single_quote and not in_double_quote:
                                            semicolons.append(i)
                                    
                                    if semicolons:
                                        # 取第一个不在引号内的分号作为分隔
                                        pkg_spec = dep[:semicolons[0]].strip()
                                        condition = dep[semicolons[0]+1:].strip()
                                    
                                    # 处理包名和版本
                                    match = re.search(r'([a-zA-Z0-9._-]+)([<>=~!][<>=~!]?.*)', pkg_spec)
                                    if match:
                                        package_name = match.group(1).strip()
                                        version = match.group(2).strip()
                                    else:
                                        package_name = pkg_spec.strip()
                                        version = "NOASSERTION"
                                    
                                    # 如果有条件，将条件添加到版本信息中
                                    if condition:
                                        version_with_condition = f"{version} ; {condition}" if version != "NOASSERTION" else f"NOASSERTION ; {condition}"
                                    else:
                                        version_with_condition = version
                                    
                                    # 创建唯一ID
                                    unique_id = hashlib.md5(f"{package_name}|{version_with_condition}|{group_name}".encode()).hexdigest()
                                    
                                    dependencies.append({
                                        "name": package_name,
                                        "SPDXID": f"SPDXRef-Package-{unique_id}",
                                        "versionInfo": version_with_condition,
                                        "downloadLocation": f"https://pypi.org/project/{package_name}/",
                                        "licenseConcluded": "NOASSERTION",
                                        "licenseDeclared": "NOASSERTION",
                                        "copyrightText": "NOASSERTION",
                                        "supplier": "Organization: PyPI",
                                        "comment": f"From {file_basename} (optional-dependencies.{group_name})"
                                    })
                    
                    logger.info(f"从 {file_basename} 中使用 toml 库解析了 {len(dependencies)} 个依赖项")
                    return dependencies
                except Exception as e:
                    logger.warning(f"使用 toml 库解析 {file_path} 时出错: {e}，将尝试简单解析方式")
            else:
                logger.warning("未安装 toml 库，将使用简单方式解析 pyproject.toml 文件")
            
            # 简单的行解析方式（作为备选方案）
            in_dependencies_section = False
            section_name = ""
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    
                    # 检查各种依赖段落
                    if (line == '[tool.poetry.dependencies]' or 
                        line == '[project.dependencies]' or 
                        line == 'dependencies = ['):
                        in_dependencies_section = True
                        section_name = line.strip('[]')
                        continue
                    elif line.startswith('[') and line.endswith(']'):
                        in_dependencies_section = False
                        section_name = ""
                        continue
                    
                    if in_dependencies_section:
                        # 匹配依赖项行
                        if '=' in line or line.strip().startswith('"') or line.strip().startswith("'"):
                            # 清理行中的引号、逗号等
                            clean_line = line.strip().strip(',').strip('"\'')
                            
                            # 尝试匹配格式为 "package = version" 的行
                            parts = re.split(r'\s*=\s*', clean_line, 1)
                            
                            if len(parts) == 2:
                                package_name = parts[0].strip().strip('"\'')
                                version_part = parts[1].strip().strip('"\'')
                                
                                if package_name == 'python':  # 跳过 python 解释器版本
                                    continue
                                
                                # 分离条件依赖
                                condition = None
                                if ';' in version_part:
                                    version_parts = version_part.split(';', 1)
                                    version = version_parts[0].strip()
                                    condition = version_parts[1].strip()
                                else:
                                    version = version_part
                                
                                # 如果有条件，将条件添加到版本信息中
                                if condition:
                                    version_with_condition = f"{version} ; {condition}"
                                else:
                                    version_with_condition = version
                                
                                # 创建唯一ID
                                unique_id = hashlib.md5(f"{package_name}|{version_with_condition}|{section_name}".encode()).hexdigest()
                                
                                dependencies.append({
                                    "name": package_name,
                                    "SPDXID": f"SPDXRef-Package-{unique_id}",
                                    "versionInfo": version_with_condition,
                                    "downloadLocation": f"https://pypi.org/project/{package_name}/",
                                    "licenseConcluded": "NOASSERTION",
                                    "licenseDeclared": "NOASSERTION",
                                    "copyrightText": "NOASSERTION",
                                    "supplier": "Organization: PyPI",
                                    "comment": f"From {file_basename} ({section_name})"
                                })
                            else:
                                # 尝试匹配列表项格式: "package>=version"
                                clean_line = clean_line.strip('"\'').strip(',')
                                
                                # 分离条件依赖
                                condition = None
                                if ';' in clean_line:
                                    parts = clean_line.split(';', 1)
                                    pkg_spec = parts[0].strip()
                                    condition = parts[1].strip()
                                else:
                                    pkg_spec = clean_line
                                
                                # 处理包名和版本
                                match = re.search(r'([a-zA-Z0-9._-]+)([<>=~!][<>=~!]?.*)?', pkg_spec)
                                if match:
                                    package_name = match.group(1).strip()
                                    version = match.group(2).strip() if match.group(2) else "NOASSERTION"
                                    
                                    # 如果有条件，将条件添加到版本信息中
                                    if condition:
                                        version_with_condition = f"{version} ; {condition}" if version != "NOASSERTION" else f"NOASSERTION ; {condition}"
                                    else:
                                        version_with_condition = version
                                    
                                    # 创建唯一ID
                                    unique_id = hashlib.md5(f"{package_name}|{version_with_condition}|{section_name}".encode()).hexdigest()
                                    
                                    dependencies.append({
                                        "name": package_name,
                                        "SPDXID": f"SPDXRef-Package-{unique_id}",
                                        "versionInfo": version_with_condition,
                                        "downloadLocation": f"https://pypi.org/project/{package_name}/",
                                        "licenseConcluded": "NOASSERTION",
                                        "licenseDeclared": "NOASSERTION",
                                        "copyrightText": "NOASSERTION",
                                        "supplier": "Organization: PyPI",
                                        "comment": f"From {file_basename} ({section_name})"
                                    })
            
            logger.info(f"从 {file_basename} 中使用备选方式解析了 {len(dependencies)} 个依赖项")
                        
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
    
    def _parse_package_lock_json(self, file_path):
        """解析 package-lock.json 文件"""
        dependencies = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                data = json.loads(content)
                
                # 获取锁定的依赖项
                if 'dependencies' in data and isinstance(data['dependencies'], dict):
                    for name, info in data['dependencies'].items():
                        if not isinstance(name, str) or not name:
                            continue
                        
                        # 获取版本信息
                        version = info.get('version', 'NOASSERTION')
                        
                        # 获取依赖项的基本信息
                        resolved = info.get('resolved', f"https://www.npmjs.com/package/{name}")
                        integrity = info.get('integrity', 'NOASSERTION')
                        
                        # 获取许可证信息
                        license_declared = 'NOASSERTION'
                        if 'license' in info:
                            license_declared = info['license']
                        
                        dependencies.append({
                            "name": name,
                            "SPDXID": f"SPDXRef-Package-{name}",
                            "versionInfo": version,
                            "downloadLocation": resolved,
                            "licenseConcluded": license_declared,
                            "licenseDeclared": license_declared,
                            "copyrightText": "NOASSERTION",
                            "supplier": "Organization: npm",
                            "comment": f"Integrity: {integrity}"
                        })
                
                # 处理 npm 7+ 版本中的依赖项扁平化列表
                if 'packages' in data and isinstance(data['packages'], dict):
                    for path, info in data['packages'].items():
                        if path == "":  # 根包
                            continue
                        
                        # 从路径中提取包名
                        if path.startswith('node_modules/'):
                            parts = path.split('/')
                            if len(parts) > 1:
                                name = parts[1]  # 获取包名
                            else:
                                continue
                        else:
                            name = path
                        
                        # 获取版本信息
                        version = info.get('version', 'NOASSERTION')
                        
                        # 获取依赖项的其他信息
                        resolved = info.get('resolved', f"https://www.npmjs.com/package/{name}")
                        integrity = info.get('integrity', 'NOASSERTION')
                        
                        # 获取许可证信息
                        license_declared = 'NOASSERTION'
                        if 'license' in info:
                            license_declared = info['license']
                        
                        # 添加依赖项
                        spdx_id = f"SPDXRef-Package-{name}"
                        
                        # 避免重复添加
                        if not any(d['SPDXID'] == spdx_id for d in dependencies):
                            dependencies.append({
                                "name": name,
                                "SPDXID": spdx_id,
                                "versionInfo": version,
                                "downloadLocation": resolved,
                                "licenseConcluded": license_declared,
                                "licenseDeclared": license_declared,
                                "copyrightText": "NOASSERTION",
                                "supplier": "Organization: npm",
                                "comment": f"Integrity: {integrity}"
                            })
        
        except Exception as e:
            logger.warning(f"解析 package-lock.json 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_gemfile(self, file_path):
        """解析 Gemfile 或 Gemfile.lock 文件"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if file_path.endswith('.lock'):
                # 解析 Gemfile.lock
                # 找到 GEM 部分
                gem_section_match = re.search(r'GEM\s+remote:.*?\n(.*?)(?:\n\n|\Z)', content, re.DOTALL)
                if gem_section_match:
                    gem_section = gem_section_match.group(1)
                    
                    # 解析规范部分
                    specs_section = re.search(r'PLATFORMS.*?\n(.*?)(?:\n\n|\Z)', content, re.DOTALL)
                    if specs_section:
                        specs = specs_section.group(1)
                        
                        # 匹配每个依赖项
                        for match in re.finditer(r'^\s{4}([^\s(]+)(?:\s+\(([^)]+)\))?', specs, re.MULTILINE):
                            name = match.group(1)
                            version = match.group(2) if match.group(2) else "NOASSERTION"
                            
                            dependencies.append({
                                "name": name,
                                "SPDXID": f"SPDXRef-Package-{name}",
                                "versionInfo": version,
                                "downloadLocation": f"https://rubygems.org/gems/{name}",
                                "licenseConcluded": "NOASSERTION",
                                "licenseDeclared": "NOASSERTION",
                                "copyrightText": "NOASSERTION",
                                "supplier": "Organization: RubyGems"
                            })
            else:
                # 解析 Gemfile
                # 找到 gem 声明
                for match in re.finditer(r'^\s*gem\s+[\'"](.*?)[\'"](?:,\s*[\'"]?([^\'",]+)[\'"]?)?', content, re.MULTILINE):
                    name = match.group(1)
                    version = match.group(2) if match.group(2) else "NOASSERTION"
                    
                    dependencies.append({
                        "name": name,
                        "SPDXID": f"SPDXRef-Package-{name}",
                        "versionInfo": version,
                        "downloadLocation": f"https://rubygems.org/gems/{name}",
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                        "supplier": "Organization: RubyGems"
                    })
        except Exception as e:
            logger.warning(f"解析 Gemfile 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_gemspec(self, file_path):
        """解析 .gemspec 文件"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 查找依赖项声明
            # 匹配 add_dependency, add_runtime_dependency, add_development_dependency
            for match in re.finditer(r'(?:add_dependency|add_runtime_dependency|add_development_dependency)\s*\(?[\'"](.*?)[\'"](?:,\s*[\'"]?([^\'",]+)[\'"]?)?', content):
                name = match.group(1)
                version = match.group(2) if match.group(2) else "NOASSERTION"
                
                dependencies.append({
                    "name": name,
                    "SPDXID": f"SPDXRef-Package-{name}",
                    "versionInfo": version,
                    "downloadLocation": f"https://rubygems.org/gems/{name}",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "supplier": "Organization: RubyGems"
                })
                
            # 尝试获取许可证信息
            license_match = re.search(r'license\s*=\s*[\'"]([^\'"]+)[\'"]', content)
            if license_match:
                license_info = license_match.group(1)
                
                # 更新所有依赖项的许可证信息
                for dep in dependencies:
                    dep["licenseDeclared"] = license_info
                    dep["licenseConcluded"] = license_info
            
            # 尝试获取作者信息
            author_match = re.search(r'author\s*=\s*[\'"]([^\'"]+)[\'"]', content)
            if author_match:
                author = author_match.group(1)
                
                # 更新依赖项的版权信息
                for dep in dependencies:
                    dep["copyrightText"] = f"Copyright (c) {author}"
        except Exception as e:
            logger.warning(f"解析 gemspec 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_composer_json(self, file_path):
        """解析 composer.json 或 composer.lock 文件"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                data = json.loads(content)
            
            if file_path.endswith('.lock'):
                # 解析 composer.lock
                if 'packages' in data and isinstance(data['packages'], list):
                    for package in data['packages']:
                        name = package.get('name', '')
                        if not name:
                            continue
                        
                        version = package.get('version', 'NOASSERTION')
                        license_info = package.get('license', ['NOASSERTION'])
                        if isinstance(license_info, list) and license_info:
                            license_declared = ', '.join(license_info)
                        elif isinstance(license_info, str):
                            license_declared = license_info
                        else:
                            license_declared = 'NOASSERTION'
                        
                        # 获取源信息
                        source = package.get('source', {})
                        download_url = source.get('url', f"https://packagist.org/packages/{name}")
                        
                        # 尝试获取作者信息
                        authors = package.get('authors', [])
                        supplier = "Organization: Packagist"
                        if authors and isinstance(authors, list) and 'name' in authors[0]:
                            supplier = f"Person: {authors[0]['name']}"
                        
                        dependencies.append({
                            "name": name,
                            "SPDXID": f"SPDXRef-Package-{name}",
                            "versionInfo": version,
                            "downloadLocation": download_url,
                            "licenseConcluded": license_declared,
                            "licenseDeclared": license_declared,
                            "copyrightText": "NOASSERTION",
                            "supplier": supplier
                        })
            else:
                # 解析 composer.json
                # 获取 require 部分
                if 'require' in data and isinstance(data['require'], dict):
                    for name, version in data['require'].items():
                        if name == 'php':  # 跳过 PHP 版本要求
                            continue
                            
                        dependencies.append({
                            "name": name,
                            "SPDXID": f"SPDXRef-Package-{name}",
                            "versionInfo": version,
                            "downloadLocation": f"https://packagist.org/packages/{name}",
                            "licenseConcluded": "NOASSERTION",
                            "licenseDeclared": "NOASSERTION",
                            "copyrightText": "NOASSERTION",
                            "supplier": "Organization: Packagist"
                        })
                
                # 获取 require-dev 部分
                if 'require-dev' in data and isinstance(data['require-dev'], dict):
                    for name, version in data['require-dev'].items():
                        dependencies.append({
                            "name": name,
                            "SPDXID": f"SPDXRef-Package-{name}",
                            "versionInfo": version,
                            "downloadLocation": f"https://packagist.org/packages/{name}",
                            "licenseConcluded": "NOASSERTION",
                            "licenseDeclared": "NOASSERTION",
                            "copyrightText": "NOASSERTION",
                            "supplier": "Organization: Packagist"
                        })
        except Exception as e:
            logger.warning(f"解析 composer.json/lock 文件 {file_path} 时出错: {e}")
        
        return dependencies
    
    def _parse_cargo_toml(self, file_path):
        """解析 Cargo.toml 或 Cargo.lock 文件"""
        dependencies = []
        
        try:
            if file_path.endswith('.lock'):
                # 解析 Cargo.lock
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # 查找所有 [[package]] 块
                for package_match in re.finditer(r'\[\[package\]\](.*?)(?=\[\[package\]\]|\Z)', content, re.DOTALL):
                    package_content = package_match.group(1)
                    
                    # 提取包名称
                    name_match = re.search(r'name\s*=\s*"([^"]+)"', package_content)
                    if not name_match:
                        continue
                    
                    name = name_match.group(1)
                    
                    # 提取版本信息
                    version_match = re.search(r'version\s*=\s*"([^"]+)"', package_content)
                    version = version_match.group(1) if version_match else "NOASSERTION"
                    
                    # 提取源信息
                    source_match = re.search(r'source\s*=\s*"([^"]+)"', package_content)
                    source = source_match.group(1) if source_match else None
                    
                    download_url = source if source else f"https://crates.io/crates/{name}"
                    
                    dependencies.append({
                        "name": name,
                        "SPDXID": f"SPDXRef-Package-{name}",
                        "versionInfo": version,
                        "downloadLocation": download_url,
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                        "supplier": "Organization: crates.io"
                    })
            else:
                # 解析 Cargo.toml
                # 尝试使用toml库解析
                if toml:
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = toml.load(f)
                        
                        # 处理依赖部分
                        if 'dependencies' in data and isinstance(data['dependencies'], dict):
                            for name, info in data['dependencies'].items():
                                # 处理不同格式的版本信息
                                if isinstance(info, str):
                                    version = info
                                elif isinstance(info, dict) and 'version' in info:
                                    version = info['version']
                                else:
                                    version = "NOASSERTION"
                                
                                dependencies.append({
                                    "name": name,
                                    "SPDXID": f"SPDXRef-Package-{name}",
                                    "versionInfo": version,
                                    "downloadLocation": f"https://crates.io/crates/{name}",
                                    "licenseConcluded": "NOASSERTION",
                                    "licenseDeclared": "NOASSERTION",
                                    "copyrightText": "NOASSERTION",
                                    "supplier": "Organization: crates.io"
                                })
                        
                        # 处理开发依赖
                        if 'dev-dependencies' in data and isinstance(data['dev-dependencies'], dict):
                            for name, info in data['dev-dependencies'].items():
                                # 处理不同格式的版本信息
                                if isinstance(info, str):
                                    version = info
                                elif isinstance(info, dict) and 'version' in info:
                                    version = info['version']
                                else:
                                    version = "NOASSERTION"
                                
                                dependencies.append({
                                    "name": name,
                                    "SPDXID": f"SPDXRef-Package-{name}",
                                    "versionInfo": version,
                                    "downloadLocation": f"https://crates.io/crates/{name}",
                                    "licenseConcluded": "NOASSERTION",
                                    "licenseDeclared": "NOASSERTION",
                                    "copyrightText": "NOASSERTION",
                                    "supplier": "Organization: crates.io"
                                })
                    except Exception as e:
                        logger.warning(f"使用 toml 库解析 {file_path} 时出错: {e}，将尝试简单解析方式")
                
                # 如果toml库不可用或解析失败，使用正则表达式进行简单解析
                if not dependencies:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # 查找依赖部分
                    dep_section_match = re.search(r'\[dependencies\](.*?)(?=\[|\Z)', content, re.DOTALL)
                    if dep_section_match:
                        dep_section = dep_section_match.group(1)
                        
                        # 解析每个依赖项
                        for line in dep_section.split('\n'):
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                                
                            # 匹配 "name = ..." 格式
                            dep_match = re.match(r'([^\s=]+)\s*=\s*(.+)', line)
                            if dep_match:
                                name = dep_match.group(1)
                                version_info = dep_match.group(2).strip()
                                
                                # 处理不同的版本声明格式
                                if version_info.startswith('"') and version_info.endswith('"'):
                                    # 简单的字符串版本
                                    version = version_info.strip('"')
                                elif version_info.startswith('{') and version_info.endswith('}'):
                                    # 表格格式
                                    version_match = re.search(r'version\s*=\s*"([^"]+)"', version_info)
                                    version = version_match.group(1) if version_match else "NOASSERTION"
                                else:
                                    version = version_info
                                
                                dependencies.append({
                                    "name": name,
                                    "SPDXID": f"SPDXRef-Package-{name}",
                                    "versionInfo": version,
                                    "downloadLocation": f"https://crates.io/crates/{name}",
                                    "licenseConcluded": "NOASSERTION",
                                    "licenseDeclared": "NOASSERTION",
                                    "copyrightText": "NOASSERTION",
                                    "supplier": "Organization: crates.io"
                                })
        except Exception as e:
            logger.warning(f"解析 Cargo.toml/lock 文件 {file_path} 时出错: {e}")
        
        return dependencies
        
    def _parse_pubspec_yaml(self, file_path):
        """解析 pubspec.yaml 文件"""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            # 解析依赖部分
            if 'dependencies' in data and isinstance(data['dependencies'], dict):
                for name, info in data['dependencies'].items():
                    # 跳过SDK依赖
                    if name == 'flutter' or name == 'dart':
                        continue
                    
                    # 处理不同格式的版本信息
                    if isinstance(info, str):
                        version = info
                    elif isinstance(info, dict) and 'version' in info:
                        version = info['version']
                    else:
                        version = "NOASSERTION"
                    
                    dependencies.append({
                        "name": name,
                        "SPDXID": f"SPDXRef-Package-{name}",
                        "versionInfo": version,
                        "downloadLocation": f"https://pub.dev/packages/{name}",
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                        "supplier": "Organization: pub.dev"
                    })
            
            # 解析开发依赖
            if 'dev_dependencies' in data and isinstance(data['dev_dependencies'], dict):
                for name, info in data['dev_dependencies'].items():
                    # 处理不同格式的版本信息
                    if isinstance(info, str):
                        version = info
                    elif isinstance(info, dict) and 'version' in info:
                        version = info['version']
                    else:
                        version = "NOASSERTION"
                    
                    dependencies.append({
                        "name": name,
                        "SPDXID": f"SPDXRef-Package-{name}",
                        "versionInfo": version,
                        "downloadLocation": f"https://pub.dev/packages/{name}",
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                        "supplier": "Organization: pub.dev"
                    })
        except Exception as e:
            logger.warning(f"解析 pubspec.yaml 文件 {file_path} 时出错: {e}")
        
        return dependencies 

    def _parse_yarn_lock(self, file_path):
        """解析 yarn.lock 文件"""
        dependencies = []
        file_basename = os.path.basename(file_path)
        logger.info(f"开始解析 {file_basename}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # yarn.lock格式解析
            # 每个包依赖项的格式通常是：
            # "package-name@^1.0.0", "package-name@~1.0.0", "package-name@1.0.0":
            #   version "1.0.2"
            #   resolved "https://registry.yarnpkg.com/package-name/-/package-name-1.0.2.tgz#..."
            #   integrity sha1-...
            #   dependencies:
            #     dependency-name "^2.0.0"
            
            # 使用正则表达式匹配依赖项
            dep_pattern = re.compile(r'"?([^"@]+)(?:@[^"]*)"?(?:,\s*"[^"]+")*:\n\s+version\s+"([^"]+)"\n\s+resolved\s+"([^"]+)"', re.MULTILINE)
            matches = dep_pattern.finditer(content)
            
            processed_packages = set()  # 用于跟踪已处理的包名+版本组合
            
            for match in matches:
                package_name = match.group(1).strip()
                version = match.group(2).strip()
                resolved_url = match.group(3).strip()
                
                # 确保我们只添加每个包的一个版本
                package_key = f"{package_name}|{version}"
                if package_key in processed_packages:
                    continue
                
                processed_packages.add(package_key)
                
                # 创建依赖项，使用唯一ID以避免重复
                unique_id = hashlib.md5(f"{package_name}|{version}".encode()).hexdigest()
                
                dependency = {
                    "name": package_name,
                    "SPDXID": f"SPDXRef-Package-{unique_id}",
                    "versionInfo": version,
                    "downloadLocation": resolved_url,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                    "supplier": "Organization: npm",
                    "comment": f"From {file_basename}"
                }
                
                dependencies.append(dependency)
            
            # 备用解析方法（如果上述方法没有找到依赖项）
            if not dependencies:
                logger.info(f"使用备用方法解析 {file_basename}")
                # 简单的包名匹配
                simple_dep_pattern = re.compile(r'"?([^"@\s]+)@[^:]+"?:')
                version_pattern = re.compile(r'version "([^"]+)"')
                resolved_pattern = re.compile(r'resolved "([^"]+)"')
                
                lines = content.split('\n')
                i = 0
                while i < len(lines):
                    line = lines[i]
                    
                    # 查找包声明行
                    package_match = simple_dep_pattern.search(line)
                    if package_match:
                        package_name = package_match.group(1).strip()
                        
                        # 查找版本和resolved URL
                        version = "NOASSERTION"
                        resolved_url = f"https://www.npmjs.com/package/{package_name}"
                        
                        # 查找接下来几行中的版本和URL
                        for j in range(1, min(5, len(lines) - i)):
                            next_line = lines[i + j]
                            
                            version_match = version_pattern.search(next_line)
                            if version_match:
                                version = version_match.group(1).strip()
                            
                            resolved_match = resolved_pattern.search(next_line)
                            if resolved_match:
                                resolved_url = resolved_match.group(1).strip()
                        
                        # 创建依赖项，使用唯一ID以避免重复
                        package_key = f"{package_name}|{version}"
                        if package_key not in processed_packages:
                            processed_packages.add(package_key)
                            
                            unique_id = hashlib.md5(f"{package_name}|{version}".encode()).hexdigest()
                            
                            dependency = {
                                "name": package_name,
                                "SPDXID": f"SPDXRef-Package-{unique_id}",
                                "versionInfo": version,
                                "downloadLocation": resolved_url,
                                "licenseConcluded": "NOASSERTION",
                                "licenseDeclared": "NOASSERTION",
                                "copyrightText": "NOASSERTION",
                                "supplier": "Organization: npm",
                                "comment": f"From {file_basename} (备用解析)"
                            }
                            
                            dependencies.append(dependency)
                    
                    i += 1
            
            logger.info(f"从 {file_basename} 中解析了 {len(dependencies)} 个依赖项")
            
        except Exception as e:
            logger.warning(f"解析 yarn.lock 文件 {file_path} 时出错: {e}")
            logger.debug(f"详细错误: {traceback.format_exc()}")
        
        return dependencies