# SBOM Generator

Software Bill of Materials (SBOM) 生成器，用于从GitHub仓库创建符合SPDX-2.3格式的SBOM文档。

## 功能特点

- 支持从GitHub仓库生成SBOM
- 生成符合SPDX-2.3规范的SBOM
- 基于仓库内容自动识别编程语言和依赖关系
- 支持多种包管理器文件解析（requirements.txt, package.json, pom.xml等）
- 输出格式支持JSON和TAG-VALUE

## 安装

1. 克隆仓库：
   ```
   git clone https://github.com/yourusername/SBOMGenerator.git
   cd SBOMGenerator
   ```

2. 安装依赖：
   ```
   pip install -r requirements.txt
   ```

## 配置

在 `config.yaml` 文件中配置：

```yaml
# GitHub配置
github_token: "your-github-token"  # 在这里设置你的GitHub令牌

# SBOM配置
namespace_prefix: "https://spdx.org/spdxdocs"
creator_name: "Your Name"
creator_email: "your-email@example.com"

# 日志配置
log_level: "INFO"  # DEBUG, INFO, WARNING, ERROR

# 输出配置
output_dir: "output"
output_format: "json"  # json, tag-value
```

## 使用方法

### 简化版SBOM生成器：

```bash
python simple_sbom_generator.py --org 组织名 --repo 仓库名 --token GitHub令牌
```

示例：
```bash
python simple_sbom_generator.py --org microsoft --repo vscode --token ghp_123456789abcdef
```

完整参数列表：
```
--org, -o       GitHub组织/用户名（必需）
--repo, -r      GitHub仓库名（必需）
--output, -f    输出文件路径（默认: output/{org}_{repo}_sbom.json）
--token, -t     GitHub个人访问令牌
--config, -c    配置文件路径（默认: config.yaml）
--temp-dir, -d  临时目录路径（默认: Temp）
--format        SBOM输出格式: json或tag-value（默认: json）
--log-level     日志级别: DEBUG, INFO, WARNING, ERROR（默认: INFO）
```

## 目录结构

```
SBOMGenerator/
├── simple_sbom_generator.py   # 简化版SBOM生成器入口脚本
├── config.yaml               # 配置文件
├── requirements.txt          # 依赖列表
├── README.md                 # 说明文档
├── src/                      # 源码目录
│   ├── github_client.py      # GitHub客户端
│   ├── simple_sbom_generator.py # 简化版SBOM生成器核心实现
│   └── utils.py              # 实用工具函数
├── logs/                     # 日志目录
├── output/                   # 输出目录
└── Temp/                     # 临时文件目录
```

## 生成的SBOM包含内容

生成的SBOM将包含以下信息：

- 文档元数据（符合SPDX-2.3规范）
- 仓库基本信息
- 主要编程语言
- 文件清单和校验和
- 依赖包信息（从包管理器文件中提取）
- 许可证信息（如可获取）
- 关系信息

## 贡献

欢迎贡献代码、报告问题或提出改进建议！

## 许可证

MIT 