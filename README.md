如何进行部署
因为涉及到 AWS 的网关、Lambda 函数和 DynamoDB 的连动权限配置，使用原生的 AWS 控制台手动配置会非常繁琐。推荐使用 Serverless Framework 工具通过命令行自动化部署。

1. 前置准备
确保你的电脑上安装了 Node.js (>= 18.x)。

拥有一个 AWS 账号，并在本地配置好 AWS 凭证（Access Key 和 Secret Key）。

Bash
# 配置你的 AWS CLI 环境
aws configure
2. 安装部署工具并拉取依赖
打开终端，进入到刚刚新建了文件的目录 (totp-aws-lambda) 中。

Bash
# 全局安装 Serverless 框架
npm install -g serverless

# 安装项目所需的依赖 (生成 node_modules 文件夹)
npm install
3. 执行部署
运行以下命令，Serverless 会根据 serverless.yml 自动在云端构建一切资源：

Bash
serverless deploy
等待大约 1-3 分钟，命令行会输出绿色的 endpoints:，类似这样：

https://xxxxxx.execute-api.ap-northeast-1.amazonaws.com/

这就是你的应用公网地址。
