"""
GitHub 客户端模块，用于与 GitHub API 交互获取仓库数据
"""

import os
import logging
import time
import shutil
import tempfile
import re
import requests
import zipfile
from pathlib import Path
from git import Repo, GitCommandError
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class GitHubClient:
    """GitHub 客户端类，用于与 GitHub API 交互和下载仓库"""
    
    def __init__(self, token=None, rate_limit_wait=True):
        """
        初始化 GitHub 客户端
        
        Args:
            token (str, optional): GitHub 访问令牌
            rate_limit_wait (bool, optional): 是否在达到 API 速率限制时等待
        """
        self.token = token
        self.rate_limit_wait = rate_limit_wait
        self.api_base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
            logger.info("GitHub 客户端已初始化（使用令牌）")
        else:
            logger.info("GitHub 客户端已初始化（无令牌）")
    
    def _make_request(self, endpoint, method="GET", params=None, data=None):
        """
        向 GitHub API 发送请求
        
        Args:
            endpoint (str): API 端点
            method (str, optional): HTTP 方法
            params (dict, optional): 查询参数
            data (dict, optional): 请求数据
            
        Returns:
            dict: API 响应
        """
        url = f"{self.api_base_url}/{endpoint}"
        logger.debug(f"向 {url} 发送 {method} 请求")
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                params=params,
                json=data
            )
            
            # 处理速率限制
            if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
                remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                
                if remaining == 0 and self.rate_limit_wait:
                    wait_time = max(reset_time - time.time(), 0) + 5
                    logger.warning(f"达到 GitHub API 速率限制，等待 {wait_time:.0f} 秒")
                    time.sleep(wait_time)
                    # 重试请求
                    return self._make_request(endpoint, method, params, data)
            
            # 检查是否成功
            response.raise_for_status()
            
            # 尝试解析 JSON 响应
            if response.text.strip():
                return response.json()
            return {}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API 请求失败: {e}")
            raise
    
    def get_repository_metadata(self, org, repo):
        """
        获取仓库元数据
        
        Args:
            org (str): 组织名称
            repo (str): 仓库名称
            
        Returns:
            dict: 仓库元数据
        """
        try:
            logger.info(f"获取 {org}/{repo} 仓库信息")
            endpoint = f"repos/{org}/{repo}"
            repo_data = self._make_request(endpoint)
            
            # 获取仓库语言数据
            languages_data = self._make_request(f"{endpoint}/languages")
            
            # 获取仓库许可证信息
            license_info = repo_data.get("license", {})
            license_key = license_info.get("key") if license_info else None
            
            # 提取所需的元数据
            metadata = {
                "name": repo_data.get("name"),
                "full_name": repo_data.get("full_name"),
                "description": repo_data.get("description"),
                "html_url": repo_data.get("html_url"),
                "clone_url": repo_data.get("clone_url"),
                "ssh_url": repo_data.get("ssh_url"),
                "default_branch": repo_data.get("default_branch"),
                "created_at": repo_data.get("created_at"),
                "updated_at": repo_data.get("updated_at"),
                "pushed_at": repo_data.get("pushed_at"),
                "languages": languages_data,
                "license": license_key,
                "stars": repo_data.get("stargazers_count"),
                "forks": repo_data.get("forks_count"),
                "open_issues": repo_data.get("open_issues_count"),
                "watchers": repo_data.get("watchers_count"),
                "size": repo_data.get("size"),
                "private": repo_data.get("private"),
                "owner": {
                    "login": repo_data.get("owner", {}).get("login"),
                    "type": repo_data.get("owner", {}).get("type"),
                    "url": repo_data.get("owner", {}).get("html_url")
                }
            }
            
            logger.info(f"成功获取仓库元数据: {org}/{repo}")
            return metadata
            
        except Exception as e:
            logger.error(f"获取仓库元数据时出错: {e}")
            raise
    
    def download_repository(self, org, repo, output_dir, branch=None):
        """
        下载 GitHub 仓库
        
        Args:
            org (str): 组织名称
            repo (str): 仓库名称
            output_dir (str): 输出目录路径
            branch (str, optional): 要下载的分支
            
        Returns:
            str: 下载的仓库本地路径
        """
        # 确保输出目录存在
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        repo_path = os.path.join(output_dir, repo)
        
        # 如果有令牌，使用 Git 克隆
        if self.token:
            return self._clone_repository(org, repo, repo_path, branch)
        else:
            # 否则使用 ZIP 下载
            return self._download_repository_zip(org, repo, repo_path, branch)
    
    def _clone_repository(self, org, repo, repo_path, branch=None):
        """
        使用 Git 克隆仓库
        
        Args:
            org (str): 组织名称
            repo (str): 仓库名称
            repo_path (str): 本地仓库路径
            branch (str, optional): 要克隆的分支
            
        Returns:
            str: 克隆的仓库本地路径
        """
        try:
            # 如果目录已存在，先删除
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
            
            # 创建 Git URL
            git_url = f"https://{self.token}@github.com/{org}/{repo}.git"
            
            logger.info(f"正在克隆仓库 {org}/{repo}")
            
            # 克隆仓库
            clone_args = ['--depth', '1']  # 浅克隆以减少数据传输
            
            if branch:
                clone_args.extend(['--branch', branch])
            
            Repo.clone_from(git_url, repo_path, depth=1, branch=branch)
            
            logger.info(f"成功克隆仓库到 {repo_path}")
            return repo_path
            
        except GitCommandError as e:
            logger.error(f"克隆仓库时出错: {e}")
            raise
    
    def _download_repository_zip(self, org, repo, repo_path, branch=None):
        """
        下载仓库的 ZIP 归档
        
        Args:
            org (str): 组织名称
            repo (str): 仓库名称
            repo_path (str): 本地仓库路径
            branch (str, optional): 要下载的分支
            
        Returns:
            str: 解压的仓库本地路径
        """
        try:
            # 如果目录已存在，先删除
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
            
            # 创建一个临时文件来保存 ZIP
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_zip:
                temp_zip_path = temp_zip.name
            
            # 确定分支
            ref = branch if branch else "HEAD"
            
            # 构建 ZIP URL
            zip_url = f"https://github.com/{org}/{repo}/archive/{ref}.zip"
            
            # 设置用于下载的头信息
            download_headers = {}
            if self.token:
                download_headers["Authorization"] = f"Bearer {self.token}"
            
            logger.info(f"正在下载仓库 ZIP 归档: {org}/{repo}")
            
            # 下载 ZIP 文件
            response = requests.get(zip_url, headers=download_headers, stream=True)
            response.raise_for_status()
            
            # 写入 ZIP 文件
            with open(temp_zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # 解压 ZIP 文件
            with zipfile.ZipFile(temp_zip_path, 'r') as zip_ref:
                # ZIP 内的顶级目录名称
                top_dir = zip_ref.namelist()[0].split('/')[0]
                
                # 解压到临时目录
                temp_extract_dir = os.path.join(os.path.dirname(repo_path), f"temp_extract_{org}_{repo}")
                if os.path.exists(temp_extract_dir):
                    shutil.rmtree(temp_extract_dir)
                os.makedirs(temp_extract_dir)
                
                zip_ref.extractall(temp_extract_dir)
                
                # 移动解压后的目录到目标路径
                extracted_repo_path = os.path.join(temp_extract_dir, top_dir)
                shutil.move(extracted_repo_path, repo_path)
                
                # 清理临时目录
                if os.path.exists(temp_extract_dir):
                    shutil.rmtree(temp_extract_dir)
            
            # 删除临时 ZIP 文件
            if os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)
            
            logger.info(f"成功下载并解压仓库到 {repo_path}")
            return repo_path
            
        except Exception as e:
            logger.error(f"下载仓库 ZIP 时出错: {e}")
            raise 