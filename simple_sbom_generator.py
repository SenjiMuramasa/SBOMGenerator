#!/usr/bin/env python
"""
简化版 SBOM 生成器 CLI
通过命令行参数指定GitHub仓库信息，生成SPDX 2.3格式的SBOM
"""

import os
import sys
import argparse
import logging
import yaml
from pathlib import Path

from src.github_client import GitHubClient
from src.simple_sbom_generator import SimpleSBOMGenerator
from src.utils import setup_logging

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='简化版SBOM生成器 - 为GitHub仓库或本地项目生成SPDX 2.3格式的SBOM')
    
    # 创建互斥组，用户只能选择GitHub仓库或本地路径模式
    mode_group = parser.add_mutually_exclusive_group(required=True)
    
    # GitHub仓库模式参数
    mode_group.add_argument('--github', action='store_true', help='GitHub仓库模式')
    mode_group.add_argument('--local', action='store_true', help='本地项目模式')
    
    # GitHub仓库相关参数
    github_group = parser.add_argument_group('GitHub仓库选项')
    github_group.add_argument('--org', '-o', help='GitHub组织/用户名')
    github_group.add_argument('--repo', '-r', help='GitHub仓库名')
    github_group.add_argument('--token', '-t', help='GitHub个人访问令牌')
    github_group.add_argument('--commit', '-ct', help='GitHub仓库Commit')
    
    # 本地项目相关参数
    local_group = parser.add_argument_group('本地项目选项')
    local_group.add_argument('--path', '-p', help='本地项目路径')
    local_group.add_argument('--name', '-n', help='项目名称（可选，默认使用目录名）')
    
    # 通用参数
    parser.add_argument('--output', '-f', default=None, help='输出文件路径')
    parser.add_argument('--config', '-c', default='config.yaml', help='配置文件路径')
    parser.add_argument('--temp-dir', '-d', default='Temp', help='临时目录路径')
    parser.add_argument('--format', choices=['json', 'tag-value'], default='json', 
                      help='SBOM输出格式: json或tag-value (默认: json)')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO',
                       help='日志级别 (默认: INFO)')
    
    args = parser.parse_args()
    
    # 验证参数
    if args.github and (not args.org or not args.repo):
        parser.error("GitHub模式需要提供 --org 和 --repo 参数")
    
    if args.local and not args.path:
        parser.error("本地模式需要提供 --path 参数")
    
    return args

def load_config(config_path):
    """加载配置文件"""
    if not os.path.exists(config_path):
        return {}
    
    with open(config_path, 'r', encoding='utf-8') as f:
        try:
            return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            logging.error(f"解析配置文件时出错: {e}")
            return {}

def main():
    """主函数"""
    args = parse_arguments()
    
    # 设置日志
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    logger.info("启动简化版SBOM生成器")
    
    # 加载配置
    config = load_config(args.config)
    
    # 创建临时目录
    temp_dir = Path(args.temp_dir)
    temp_dir.mkdir(exist_ok=True)
    
    try:
        # 初始化SBOM生成器的共同参数
        namespace_prefix = config.get('namespace_prefix', 'https://spdx.org/spdxdocs')
        creator_name = config.get('creator_name', 'SBOM Generator')
        creator_email = config.get('creator_email', 'sbom-generator@example.com')
        
        if args.github:
            # GitHub仓库模式
            # 确定GitHub令牌
            github_token = args.token or config.get('github_token') or os.environ.get('GITHUB_TOKEN')
            if not github_token:
                logger.error("未提供GitHub令牌。请通过--token参数、配置文件或GITHUB_TOKEN环境变量提供")
                sys.exit(1)
                
            # 设置输出路径
            if args.output:
                output_file = args.output
            else:
                output_dir = Path('output')
                output_dir.mkdir(exist_ok=True)
                if args.commit:
                    output_file = output_dir / f"{args.org}_{args.repo}_{args.commit}.{args.format}"
                else:
                    output_file = output_dir / f"{args.org}_{args.repo}.{args.format}"
            
            # 初始化GitHub客户端
            github_client = GitHubClient(github_token)
            
            # 初始化SBOM生成器
            generator = SimpleSBOMGenerator(
                github_client=github_client,
                temp_dir=str(temp_dir),
                namespace_prefix=namespace_prefix,
                creator_name=creator_name,
                creator_email=creator_email,
                output_format=args.format
            )
            
            # 生成SBOM
            logger.info(f"开始为 {args.org}/{args.repo} 生成SBOM")
            output_path = generator.generate_sbom(args.org, args.repo, str(output_file), args.commit)
            
        elif args.local:
            # 本地项目模式
            # 设置输出路径
            if args.output:
                output_file = args.output
            else:
                output_dir = Path('output')
                output_dir.mkdir(exist_ok=True)
                project_name = args.name or os.path.basename(os.path.normpath(args.path))
                output_file = output_dir / f"{project_name}_sbom.{args.format}"
            
            # 初始化SBOM生成器
            generator = SimpleSBOMGenerator(
                github_client=None,  # 本地模式不需要GitHub客户端
                temp_dir=str(temp_dir),
                namespace_prefix=namespace_prefix,
                creator_name=creator_name,
                creator_email=creator_email,
                output_format=args.format
            )
            
            # 生成SBOM
            logger.info(f"开始为本地项目 {args.path} 生成SBOM")
            output_path = generator.generate_sbom_from_local_path(
                args.path, 
                str(output_file),
                project_name=args.name
            )
            
        logger.info(f"SBOM已成功生成: {output_path}")
        
    except Exception as e:
        logger.error(f"生成SBOM时出错: {e}", exc_info=True)
        sys.exit(1)
    finally:
        # 清理
        try:
            if 'generator' in locals():
                generator.cleanup()
        except Exception as e:
            logger.warning(f"清理临时文件时出错: {e}")

if __name__ == "__main__":
    main() 