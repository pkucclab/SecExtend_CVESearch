from typing import Dict
import json
import inspect
import logging
import asyncio
from typing import Dict, List
from mcp.types import TextContent
from src.SecExtend_Fscan.tool_registry import tool_registry

logger = logging.getLogger(__name__)
ToolDescription = '''
集成fscan的自动化扫描工具, 支持多模式漏洞检测, 端口扫描等功能.fscan工具的使用参数说明如下所示:
Usage of fscan.exe:
    -c string
            指定要执行的系统命令(支持ssh和wmiexec)
    -cookie string
            设置HTTP请求Cookie
    -dns
            启用dnslog进行漏洞验证
    -domain string
            指定域名(仅用于SMB协议)
    -eh string
            排除指定主机范围,支持CIDR格式,如: 192.168.1.1/24
    -f string
            指定输出格式 (txt/json/csv) (default "txt")
    -full
            启用完整POC扫描(如测试shiro全部100个key)
    -h string
            指定目标主机,支持以下格式:
            - 单个IP: 192.168.11.11
            - IP范围: 192.168.11.11-255
            - 多个IP: 192.168.11.11,192.168.11.12
    -hash string
            指定要破解的Hash值
    -hashf string
            从文件中读取Hash字典
    -hf string
            从文件中读取目标主机列表
    -json
            以JSON格式输出结果
    -lang string
            指定界面语言 (zh:中文, en:英文, ja:日文, ru:俄文) (default "zh")
    -local
            启用本地信息收集模式
    -log string
            日志输出级别(ALL/SUCCESS/ERROR/INFO/DEBUG) (default "SUCCESS")
    -m string
            指定扫描模式:
            预设模式:
            - All: 全量扫描
            - Basic: 基础扫描(Web/FTP/SSH等)
            - Database: 数据库扫描
            - Web: Web服务扫描
            - Service: 常见服务扫描
            - Vul: 漏洞扫描
            - Port: 端口扫描
            - ICMP: 存活探测
            - Local: 本地信息
            单项扫描:
            - web/db: mysql,redis等
            - service: ftp,ssh等
            - vul: ms17010等 (default "All")
    -no
            禁止保存扫描结果
    -nobr
            禁用密码暴力破解
    -nocolor
            禁用彩色输出显示
    -noredis
            禁用Redis安全检测
    -np
            禁用主机存活探测
    -num int
            设置POC扫描并发数 (default 20)
    -o string
            指定结果输出文件名 (default "result.txt")
    -p string
            指定扫描端口,支持以下格式:
            格式:
            - 单个: 22
            - 范围: 1-65535
            - 多个: 22,80,3306
            预设组:
            - main: 常用端口组
            - service: 服务端口组
            - db: 数据库端口组
            - web: Web端口组
            - all: 全部端口
            示例: -p main, -p 80,443, -p 1-1000 (default "21,22,23,80,81,110,135,139,143,389,443,445,502,873,993,995,1433,1521,3306,5432,5672,6379,7001,7687,8000,8005,8009,8080,8089,8443,9000,9042,9092,9200,10051,11211,15672,27017,61616")
    -path string
            指定FCG/SMB远程文件路径
    -pg
            开启进度条显示
    -ping
            使用系统ping命令替代ICMP探测
    -pocname string
            指定要使用的POC名称,如: -pocname weblogic
    -pocpath string
            指定自定义POC文件路径
    -portf string
            从文件中读取端口列表
    -proxy string
            设置HTTP代理服务器
    -pwd string
            指定单个密码
    -pwda string
            在默认密码列表基础上添加自定义密码
    -pwdf string
            从文件中读取密码字典
    -retry int
            设置最大重试次数 (default 3)
    -rf string
            指定Redis写入的SSH公钥文件
    -rs string
            指定Redis写入的计划任务内容
    -sc string
            指定MS17漏洞利用的shellcode
    -silent
            启用静默扫描模式(减少屏幕输出)
    -skip
            跳过端口指纹识别
    -socks5 string
            设置Socks5代理(用于TCP连接,将影响超时设置)
    -sshkey string
            指定SSH私钥文件路径(默认为id_rsa)
    -t int
            设置扫描线程数 (default 60)
    -time int
            设置连接超时时间(单位:秒) (default 3)
    -top int
            仅显示指定数量的存活主机 (default 10)
    -u string
            指定目标URL
    -uf string
            从文件中读取URL列表
    -user string
            指定单个用户名
    -usera string
            在默认用户列表基础上添加自定义用户名
    -userf string
            从文件中读取用户名字典
    -wmi
            启用WMI协议扫描
    -wt int
            设置Web请求超时时间(单位:秒) (default 5)

对于用户的自然语言请求, 请严格遵循参数说明, 所有的文件输出输入工作一律输出到/app/data目录下, 为了更好地满足用户需求, 以下是自然语言需求对应命令行参数和FscanTool参数的例子:
1.  用户输入: 请针对192.168.0.1/24网段进行全量扫描, 只扫描主要端口, 线程数为100, 不需要进行暴力破解, socks代理为162.23.42.12:22223, 结果保存到result_192.168.0.1_24.json文件中, 输出格式为json
    命令行参数: fscan.exe -h 192.168.0.1/24 -m All -p main -t 100 -nobr -socks5 162.23.42.12:22223 -o /app/data/result_192.168.0.1_24 -f json
    FscanTool参数: {"fscan_args": {"h": "192.168.0.1/24", "m": "All", "p": "main", "t": 100, "nobr": "", "socks5": "162.23.42.12:22223", "o": "/app/data/result_192.168.0.1_24", "f": "json"}}
2.  用户输入: 请对192.168.1.2主机进行常见服务扫描, 扫描常见服务端口, 线程数为100, 不需要探测主机是否存活, 不需要进行暴力破解, 结果保存到result_192.168.1.2.json文件中, 输出格式为json
    命令行参数: fscan.exe -h 192.168.1.2 -m Service -p service -t 100 -np -nobr -o /app/data/result_192.168.1.2.json -f json
    FscanTool参数: {"fscan_args": {"h": "192.168.1.2", "m": "Service", "p": "service", "t": 100, "np": "", "nobr": "", "o": "/app/data/result_192.168.1.2.json", "f": "json"}}
3. 用户输入: 请从url.txt文件中读取URL进行Web服务扫描, 只扫描80, 8887, 8888, 8889, 12222端口, 线程数为100, 不需要探测主机是否存活, 不需要进行暴力破解, 开启进度条显示, 不需要以文件形式保存结果
   命令行参数: fscan.exe -hf /app/data/url.txt -m Web -p 80,8887,8888,8889,12222 -t 100 -np -nobr -pg 
   FscanTool参数: {"fscan_args": {"hf":"/app/data/url.txt", "m":"Web", "p": "80,8887,8888,8889,12222", "t": 100, "np": "", "nobr": "", "pg": ""}}
'''
class FScanTool():
    def __init__(self):
        self.name="fscan"
        self.description=ToolDescription
        self.input_schema={
                "type": "object",
                "properties": {
                    "fscan_args": {"type": "object", "additionalProperties": True}
                },
                "required": ["fscan_args"]
            }

    def _build_command(self, params: Dict) -> list:
        cmd = ["fscan"]
        for arg, value in params['fscan_args'].items():
            if value != "":
                cmd += [f'-{arg}', str(value)]
            else: 
                cmd += [f'-{arg}']
        return cmd

    async def execute(self, params: Dict) -> List[TextContent]:  # 修改返回类型
        try:
            cmd = self._build_command(params)
            logger.info(f"执行命令: {' '.join(cmd)}")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                return [TextContent(type='text', text=f"扫描失败: {stderr.decode()}")]            
            return [TextContent(type='text', text=f"扫描结果: {stdout.decode()}")]
    
        except Exception as e:
            frame = inspect.trace()[-1]
            error_info = {
                "filename": frame.filename,
                "line_no": frame.lineno,
                "function": frame.function,
                "error_type": type(e).__name__,
                "error_msg": str(e)
            }
            logger.error(f"执行异常: {json.dumps(error_info, ensure_ascii=False)}")
            return [TextContent(type='text', text=f"执行异常: {json.dumps(error_info, ensure_ascii=False)}")]
            
tool_registry.register(FScanTool())
