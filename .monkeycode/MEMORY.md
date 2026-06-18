# 用户指令记忆

本文件记录了用户的指令、偏好和教导，用于在未来的交互中提供参考。

## 格式

### 用户指令条目
用户指令条目应遵循以下格式：

[用户指令摘要]
- Date: [YYYY-MM-DD]
- Context: [提及的场景或时间]
- Instructions:
  - [用户教导或指示的内容，逐行描述]

### 项目知识条目
Agent 在任务执行过程中发现的条目应遵循以下格式：

[项目知识摘要]
- Date: [YYYY-MM-DD]
- Context: Agent 在执行 [具体任务描述] 时发现
- Category: [运维部署|构建方法|测试方法|排错调试|工作流协作|环境配置]
- Instructions:
  - [具体的知识点，逐行描述]

## 去重策略
- 添加新条目前，检查是否存在相似或相同的指令
- 若发现重复，跳过新条目或与已有条目合并
- 合并时，更新上下文或日期信息
- 这有助于避免冗余条目，保持记忆文件整洁

## 条目

### catalina.sh eval 破坏 agent 参数中的分号
- Date: 2026-06-18
- Context: 使用 CATALINA_OPTS 传递 javaagent 参数时，agent args 使用分号分隔，但 catalina.sh 通过 eval 处理 CATALINA_OPTS，导致分号被解释为 shell 命令分隔符
- Category: 运维部署
- Instructions:
  - 不要通过 CATALINA_OPTS 传递包含分号的 javaagent 参数
  - 直接使用 java 命令启动 Tomcat，绕过 catalina.sh 的 eval
  - 或者使用 JAVA_OPTS（不会被 eval）代替 CATALINA_OPTS

### ClassReader.EXPAND_FRAMES 是 AdviceAdapter 的前置条件
- Date: 2026-06-18
- Context: Agent 在排查 beforeService/afterService ASM 钩子不生效时发现
- Category: 排错调试
- Instructions:
  - AdviceAdapter（继承自 LocalVariablesSorter）要求 ClassReader 使用 EXPAND_FRAMES 标志
  - cr.accept(cv, ClassReader.EXPAND_FRAMES) 是必须的，否则抛出 LocalVariablesSorter only accepts expanded frames
  - ClassWriter.COMPUTE_FRAMES + ClassReader.EXPAND_FRAMES 两者缺一不可
  - JVM 的 classfile transformer 机制会静默吞掉此异常，导致类回退到原始字节码

### Tomcat 进程清理：fuser -k 不可靠
- Date: 2026-06-18
- Context: Agent 在测试时发现多个 Tomcat 进程累积在端口上
- Category: 排错调试
- Instructions:
  - fuser -k 8080/tcp 不一定能杀死进程
  - 改用 kill -9 $(ss -tlnp | grep 8080 | grep -oP 'pid=\K\d+') 确保彻底清理
  - 每次启动 Tomcat 前必须先清理 8080 和 8005 两个端口
