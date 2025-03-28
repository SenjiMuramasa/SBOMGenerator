"""
实用工具函数模块
"""

import os
import shutil
import logging
import uuid
import re
from pathlib import Path
import sys
from datetime import datetime

logger = logging.getLogger(__name__)

def setup_logging(log_level='INFO'):
    """
    设置日志
    
    Args:
        log_level (str): 日志级别 (DEBUG, INFO, WARNING, ERROR)
    """
    # 创建日志目录
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    # 设置日志文件
    log_file = log_dir / 'sbom_generator.log'
    
    # 将字符串日志级别转换为常量
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'无效的日志级别: {log_level}')
    
    # 配置根日志
    logging.basicConfig(
        level=numeric_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

def ensure_temp_directory(temp_dir):
    """Ensure temporary directory exists"""
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
        logging.info(f"Created temporary directory: {temp_dir}")
    return temp_dir

def clean_temp_directory(temp_dir):
    """
    清理临时目录
    
    Args:
        temp_dir (str): 临时目录路径
    """
    if os.path.exists(temp_dir):
        try:
            shutil.rmtree(temp_dir)
            logging.info(f"已清理临时目录: {temp_dir}")
        except Exception as e:
            logging.warning(f"清理临时目录 {temp_dir} 时出错: {e}")

def get_timestamp():
    """Get current timestamp in ISO format"""
    return datetime.now().isoformat()

def create_repo_temp_dir(base_temp_dir, org, repo):
    """
    为仓库创建临时目录
    
    Args:
        base_temp_dir (str): 基本临时目录
        org (str): 组织名称
        repo (str): 仓库名称
    
    Returns:
        str: 仓库临时目录路径
    """
    # 生成一个唯一标识符
    unique_id = str(uuid.uuid4())[:8]
    
    # 创建临时目录路径
    repo_temp_dir = os.path.join(base_temp_dir, f"{org}_{repo}_{unique_id}")
    
    # 确保临时目录存在
    os.makedirs(repo_temp_dir, exist_ok=True)
    
    return repo_temp_dir

def detect_programming_languages(repo_dir):
    """
    通过文件扩展名检测编程语言
    
    Args:
        repo_dir (str): 仓库目录路径
    
    Returns:
        dict: 语言计数字典，如 {'Python': 10, 'JavaScript': 5}
    """
    # 语言到文件扩展名的映射
    language_extensions = {
        'Python': ['.py'],
        'JavaScript': ['.js'],
        'TypeScript': ['.ts', '.tsx'],
        'Java': ['.java'],
        'C#': ['.cs'],
        'C++': ['.cpp', '.hpp', '.cc', '.hh'],
        'C': ['.c', '.h'],
        'Go': ['.go'],
        'Ruby': ['.rb'],
        'PHP': ['.php'],
        'Swift': ['.swift'],
        'Kotlin': ['.kt', '.kts'],
        'Rust': ['.rs'],
        'Scala': ['.scala'],
        'Shell': ['.sh', '.bash'],
        'HTML': ['.html', '.htm'],
        'CSS': ['.css'],
        'XML': ['.xml'],
        'JSON': ['.json'],
        'YAML': ['.yml', '.yaml'],
        'Markdown': ['.md'],
    }
    
    # 创建扩展名到语言的映射
    extension_to_language = {}
    for language, extensions in language_extensions.items():
        for ext in extensions:
            extension_to_language[ext] = language
    
    # 初始化语言计数
    language_counts = {}
    
    # 遍历仓库目录
    for root, _, files in os.walk(repo_dir):
        for file in files:
            _, ext = os.path.splitext(file)
            ext = ext.lower()
            
            # 跳过无扩展名的文件
            if not ext:
                continue
            
            if ext in extension_to_language:
                language = extension_to_language[ext]
                language_counts[language] = language_counts.get(language, 0) + 1
    
    # 按文件数量排序
    return dict(sorted(language_counts.items(), key=lambda x: x[1], reverse=True))

def get_package_manager_files(repo_dir):
    """
    查找仓库中的包管理器文件
    
    Args:
        repo_dir (str): 仓库目录路径
    
    Returns:
        list: 包管理器文件列表，每个元素是 (包管理器名称, 文件相对路径) 元组
    """
    # 包管理器文件和对应的正则表达式模式
    package_manager_patterns = [
        # Python: 匹配标准包管理文件和以"requirements"开头的txt文件
        ('Python', re.compile(r'(requirements.*\.txt|setup\.py|Pipfile|pyproject\.toml)$')),
        # JavaScript/Node.js: 匹配标准包管理文件和锁文件
        ('JavaScript/Node.js', re.compile(r'(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock)$')),
        # Java: 匹配Maven和Gradle文件
        ('Java', re.compile(r'(pom\.xml|build\.gradle|build\.gradle\.kts|gradle\.properties|settings\.gradle|ivy\.xml)$')),
        # Go: 匹配Go模块文件
        ('Go', re.compile(r'(go\.mod|go\.sum)$')),
        # Ruby: 匹配Ruby包管理文件
        ('Ruby', re.compile(r'(Gemfile|Gemfile\.lock|.*\.gemspec)$')),
        # PHP: 匹配Composer文件
        ('PHP', re.compile(r'(composer\.json|composer\.lock)$')),
        # Rust: 匹配Cargo文件
        ('Rust', re.compile(r'(Cargo\.toml|Cargo\.lock)$')),
        # C#: 匹配.NET包管理文件
        ('C#', re.compile(r'(\.csproj|\.sln|packages\.config|paket\.dependencies|paket\.lock|nuget\.config)$')),
        # Swift: 匹配Swift包管理文件
        ('Swift', re.compile(r'(Package\.swift|Package\.resolved)$')),
        # Dart/Flutter: 匹配pub包管理文件
        ('Dart/Flutter', re.compile(r'(pubspec\.yaml|pubspec\.lock)$')),
    ]
    
    # 自定义检查函数，用于识别特定模式的文件名
    custom_file_checks = [
        # Python: 以requirements开头的txt文件
        (lambda f: f.lower().startswith('requirements') and f.lower().endswith('.txt'), 'Python'),
        # JavaScript: 以package开头的json文件
        (lambda f: f.lower().startswith('package') and f.lower().endswith('.json'), 'JavaScript/Node.js'),
        # Java: 以build开头的gradle文件
        (lambda f: f.lower().startswith('build') and f.lower().endswith('.gradle'), 'Java'),
        # C#: 以.开头的csproj或sln文件
        (lambda f: f.lower().endswith('.csproj') or f.lower().endswith('.sln'), 'C#'),
        # Ruby: 以.gemspec结尾的文件
        (lambda f: f.lower().endswith('.gemspec'), 'Ruby'),
    ]
    
    # 查找匹配的文件
    package_manager_files = []
    
    try:
        for root, dirs, files in os.walk(repo_dir):
            # 跳过某些目录
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'node_modules' and d != '__pycache__']
            
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, repo_dir)
                    
                    # 跳过太大的文件
                    try:
                        if os.path.getsize(file_path) > 10 * 1024 * 1024:  # 10MB
                            continue
                    except:
                        continue
                    
                    # 应用自定义检查函数
                    file_matched = False
                    for check_func, manager in custom_file_checks:
                        if check_func(file):
                            package_manager_files.append((manager, rel_path))
                            file_matched = True
                            break
                    
                    if file_matched:
                        continue
                    
                    # 使用正则表达式检查其他包管理文件
                    for manager, pattern in package_manager_patterns:
                        if pattern.search(file):
                            package_manager_files.append((manager, rel_path))
                            break
                except Exception as e:
                    logger.warning(f"处理文件 {file} 时出错: {e}")
    except Exception as e:
        logger.error(f"遍历仓库目录 {repo_dir} 时出错: {e}")
    
    return package_manager_files 