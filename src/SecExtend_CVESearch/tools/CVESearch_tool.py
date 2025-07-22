from typing import Dict, List
from meilisearch import Client
import logging
import os
from mcp.types import TextContent
from src.SecExtend_CVESearch.tool_registry import tool_registry

logger = logging.getLogger(__name__)

# ────────────────────────────── Meilisearch 连接信息 ──────────────────────────────
MEILISEARCH_CONFIG = {
    "host": os.getenv("MEILISEARCH_HOST", "http://meilisearch:7700"),
    "api_key": os.getenv("MEILISEARCH_API_KEY", "pkucc_crimosn_data"),  
    "index_name": "cve"
}


class CVESearchTool:
    """
    CVE 漏洞数据库查询工具（基于 Meilisearch）
    """

    def __init__(self):
        self.name = "cve_search"
        self.description = self._get_tool_description()
        self.input_schema = self._get_input_schema()

        self.client = Client(
            MEILISEARCH_CONFIG["host"],
            MEILISEARCH_CONFIG["api_key"]
        )
        self.index = self.client.index(MEILISEARCH_CONFIG["index_name"])

    # -------------------------- 基本描述 & 输入规范 --------------------------
    def _get_tool_description(self) -> str:
        return '''
            CVE 漏洞数据库查询工具（Meilisearch）

            可选参数：
            query       : 全文检索关键字（必填）
            year        : 按年份过滤（1999-2025）
            severity    : 按严重等级过滤（CRITICAL / HIGH / MEDIUM / LOW）
            score_min   : CVSS Base Score 最小值（0-10）
            score_max   : CVSS Base Score 最大值（0-10）
            limit       : 返回记录数（默认 10）
            output      : 结果保存文件路径

            示例：
            {"cve_args": {
                "query": "Apache Struts",
                "year": 2023,
                "severity": "HIGH",
                "score_min": 7.0,
                "limit": 5
                }
            }
            '''

    def _get_input_schema(self) -> Dict:
        """
        JsonSchema，用于参数校验
        """
        return {
            "type": "object",
            "properties": {
                "cve_args": {
                    "type": "object",
                    "properties": {
                        "query":      {"type": "string"},
                        "year":       {"type": "integer", "minimum": 1999},
                        "severity":   {"type": "string",
                                       "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                        "score_min":  {"type": "number", "minimum": 0, "maximum": 10},
                        "score_max":  {"type": "number", "minimum": 0, "maximum": 10},
                        "limit":      {"type": "integer", "minimum": 1, "default": 10},
                        "output":     {"type": "string"}
                    },
                    "required": ["query"],
                    "additionalProperties": False
                }
            },
            "required": ["cve_args"]
        }

    # -------------------------- 查询参数构造 --------------------------
    def _build_search_params(self, params: Dict) -> Dict:
        """
        将用户输入转换为 Meilisearch search() 的参数
        """
        search_params: Dict = {
            "limit": params.get("limit", 10),
            "attributesToRetrieve": [
                "cve_id",
                "description",
                "year",
                "cvss_severity",
                "cvss_base_score",
                "cve_mapping.functionality.gained_functionality"
            ]
        }

        filters = []

        # 年份过滤
        if (year := params.get("year")) is not None:
            filters.append(f"year = {year}")

        # 严重等级过滤
        if (severity := params.get("severity")):
            filters.append(f"cvss_severity = '{severity}'")

        # CVSS Base Score 范围过滤
        score_min = params.get("score_min")
        score_max = params.get("score_max")

        if score_min is not None and score_max is not None:
            # 自动修正大小顺序
            if score_min > score_max:
                score_min, score_max = score_max, score_min
            filters.append(
                f"cvss_base_score >= {score_min} AND cvss_base_score <= {score_max}"
            )
        elif score_min is not None:
            filters.append(f"cvss_base_score >= {score_min}")
        elif score_max is not None:
            filters.append(f"cvss_base_score <= {score_max}")

        # 合并 filter 条件
        if filters:
            # 用 AND 连接所有条件
            search_params["filter"] = " AND ".join(filters)

        return search_params

    # ------------------------------ 执行查询 ------------------------------
    async def execute(self, params: Dict) -> List[TextContent]:
        """
        供 MCP 调用的入口
        """
        try:
            cve_args = params["cve_args"]
            search_params = self._build_search_params(cve_args)

            # 调用 Meilisearch
            result = self.index.search(cve_args["query"], search_params)

            # 无结果
            if not result["hits"]:
                return [TextContent(type="text", text="未找到匹配的 CVE 记录")]

            # 格式化输出
            lines = ["🔍 CVE 查询结果:"]
            for idx, hit in enumerate(result["hits"], start=1):
                lines.append(
                    f"{idx}. [{hit['cve_id']}] {hit['description']}\n"
                    f"   年份: {hit.get('year', 'N/A')} | "
                    f"严重性: {hit.get('cvss_severity', 'N/A')} | "
                    f"CVSS: {hit.get('cvss_base_score', 'N/A')}"
                )
                # 新增功能获益输出
                try:
                    gained_func = (
                        hit.get("cve_mapping", {})
                        .get("functionality", {})
                        .get("gained_functionality")
                    )
                except Exception as e:
                    logger.error("获取功能获益时出错: %s", e)
                    gained_func = None
                if gained_func:
                    if isinstance(gained_func, list):
                        gained_func_str = ", ".join(map(str, gained_func))
                    else:
                        gained_func_str = str(gained_func)
                else:
                    gained_func_str = "N/A"
                lines.append(f"   功能获益: {gained_func_str}")

            final_text = "\n".join(lines)

            # 保存到文件
            if out_path := cve_args.get("output"):
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(final_text)
                return [TextContent(type="text", text=f"结果已保存至: {out_path}")]

            return [TextContent(type="text", text=final_text)]

        except Exception as exc:
            logger.error("Meilisearch 查询异常: %s", exc)
            return [TextContent(type="text", text=f"查询异常: {exc}")]

class CVEAddTool:
    """
    CVE 漏洞数据库增加与修改数据工具（基于 Meilisearch）,
    """

    def __init__(self):
        self.name = "cve_add_or_update"
        self.description = self._get_tool_description()
        self.input_schema = self._get_input_schema()

        self.client = Client(
            MEILISEARCH_CONFIG["host"],
            MEILISEARCH_CONFIG["api_key"]
        )
        self.index = self.client.index(MEILISEARCH_CONFIG["index_name"])

    # -------------------------- 基本描述 & 输入规范 --------------------------
    def _get_tool_description(self) -> str:
        return '''
            CVE 漏洞数据库增加与修改数据工具（Meilisearch），若已存在相同 CVE ID 的记录，则更新该记录，否则新增。

            参数结构：
            {
                'cve_data_items': [];  # CVE 数据项列表，每个项为一个字典，包含完整的 CVE 信息
            }
            每条cve数据样例：
            {"cve_id":"CVE-2020-26820","cve_mapping":{"cve_id":"CVE-2020-26820","explaination":"Unfortunately the provided CVE information does not contain enough details for me to provide a complete impact analysis using MITRE ATT&CK. However, I can make some general observations:\n\n- This appears to be a privilege escalation vulnerability affecting certain older versions of SAP NetWeaver AS Java. \n- The exploitation requires an attacker to already have administrator access to the system.\n- The impact allows the attacker to achieve remote code execution and full compromise of the system's confidentiality, integrity and availability.\n\nBased on these high-level details, a partial ATT&CK analysis could be: <EOS> The exploitation techniques and primary impact capture how the vulnerability is exploited to achieve privileged code execution. The secondary impact covers the resulting complete compromise of the system's CIA triad.\n\nHowever, without more technical details on the specific vulnerability and exploit methods, it's difficult to fully characterize this using the MITRE ATT&CK framework. Please let me know if you have any other CVE details I could analyze in more depth. <EOS> ","exploit_techniques":[],"functionality":null,"vulnerability_type":{"exploitation_techniques":[{"id":"T1068","name":"Exploitation for Privilege Escalation"}],"primary_impact":[],"secondary_impact":[],"type":"Privilege Escalation"}},"description":"SAP NetWeaver AS JAVA, versions - 7.20, 7.30, 7.31, 7.40, 7.50, allows an attacker who is authenticated as an administrator to use the administrator console, to expose unauthenticated access to the file system and upload a malicious file. The attacker or another user can then use a separate mechanism to execute OS commands through the uploaded file leading to Privilege Escalation and completely compromise the confidentiality, integrity and availability of the server operating system and any application running on it.","cvss_version":"3.1","cvss_severity":"HIGH","cvss_base_score":7.2,"year":"2020","related_attcks":[{"id":"T1068","name":"Exploitation for Privilege Escalation"}],"gt_attcks":[{"id":"T1068","name":"Exploitation for Privilege Escalation"}],"attck_patterns":[{"brief":{"long_text":"","short_text":"Adversaries exploit software vulnerabilities to elevate privileges, leveraging programming errors to execute code with higher permissions. They often start with lower access and exploit flaws, particularly in OS components or software at higher permissions, to gain SYSTEM or root access. This step is crucial when other escalation methods are limited by secure configurations. Additionally, attackers may use the Bring Your Own Vulnerable Driver (BYOVD) technique, introducing a signed but exploitable driver onto the system to execute code in kernel mode, either by initial access file delivery or by transferring the driver after compromise."},"description":"Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.\n\nWhen initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This could also enable an adversary to move from a virtualized environment, such as within a virtual machine or container, onto the underlying host. This may be a necessary step for an adversary compromising an endpoint system that has been properly configured and limits other privilege escalation methods.\n\nAdversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver (BYOVD).(Citation: ESET InvisiMole June 2020)(Citation: Unit42 AcidBox June 2020) Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via [Ingress Tool Transfer](https:\/\/attack.mitre.org\/techniques\/T1105) or [Lateral Tool Transfer](https:\/\/attack.mitre.org\/techniques\/T1570).","metadata":{"external_id":"T1068","id":"attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839","kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"privilege-escalation"}],"name":"Exploitation for Privilege Escalation","x_mitre_domains":["enterprise-attack"],"x_mitre_is_subtechnique":false,"x_mitre_platforms":["Linux","macOS","Windows","Containers"],"x_mitre_tactic_type":null},"relationships":[]}],"related_attck_patterns":[{"brief":{"long_text":"","short_text":"Adversaries exploit software vulnerabilities to elevate privileges, leveraging programming errors to execute code with higher permissions. They often start with lower access and exploit flaws, particularly in OS components or software at higher permissions, to gain SYSTEM or root access. This step is crucial when other escalation methods are limited by secure configurations. Additionally, attackers may use the Bring Your Own Vulnerable Driver (BYOVD) technique, introducing a signed but exploitable driver onto the system to execute code in kernel mode, either by initial access file delivery or by transferring the driver after compromise."},"description":"Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.\n\nWhen initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This could also enable an adversary to move from a virtualized environment, such as within a virtual machine or container, onto the underlying host. This may be a necessary step for an adversary compromising an endpoint system that has been properly configured and limits other privilege escalation methods.\n\nAdversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver (BYOVD).(Citation: ESET InvisiMole June 2020)(Citation: Unit42 AcidBox June 2020) Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via [Ingress Tool Transfer](https:\/\/attack.mitre.org\/techniques\/T1105) or [Lateral Tool Transfer](https:\/\/attack.mitre.org\/techniques\/T1570).","metadata":{"external_id":"T1068","id":"attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839","kill_chain_phases":[{"kill_chain_name":"mitre-attack","phase_name":"privilege-escalation"}],"name":"Exploitation for Privilege Escalation","x_mitre_domains":["enterprise-attack"],"x_mitre_is_subtechnique":false,"x_mitre_platforms":["Linux","macOS","Windows","Containers"],"x_mitre_tactic_type":null},"relationships":[]}],"count_attck_patterns":1,"count_related_attck_patterns":1}
            '''
    
    def _get_input_schema(self) -> Dict:
        """
        JsonSchema，用于参数校验
        """
        return {
        "type": "object",
        "properties": {
            "cve_data_items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        # -------- 基本字段 --------
                        "cve_id": {
                            "type": "string",
                            "pattern": "^CVE-[0-9]{4}-[0-9]+$"
                        },
                        "description": {"type": "string"},
                        "cvss_version": {"type": "string"},
                        "cvss_severity": {"type": "string"},
                        "cvss_base_score": {"type": "number"},
                        "year": {
                            "type": "string",
                            "pattern": "^[0-9]{4}$"
                        },

                        # -------- 主体映射信息 --------
                        "cve_mapping": {
                            "type": "object",
                            "properties": {
                                "explaination": {"type": "string"},
                                "exploit_techniques": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "id":   {"type": "string"},
                                            "name": {"type": "string"}
                                        },
                                        "required": ["id", "name"],
                                        "additionalProperties": False
                                    }
                                },

                                # ---- functionality 可为 null 或对象 ----
                                "functionality": {
                                    "anyOf": [
                                        {"type": "null"},
                                        {
                                            "type": "object",
                                            "properties": {
                                                "gained_functionality": {
                                                    "type": "array",
                                                    "items": {"type": "string"}
                                                },
                                                "primary_impact": {
                                                    "type": "array",
                                                    "items": {
                                                        "type": "object",
                                                        "properties": {
                                                            "id":   {"type": "string"},
                                                            "name": {"type": "string"}
                                                        },
                                                        "required": ["id", "name"],
                                                        "additionalProperties": False
                                                    }
                                                },
                                                "secondary_impact": {
                                                    "type": "array",
                                                    "items": {
                                                        "type": "object",
                                                        "properties": {
                                                            "id":   {"type": "string"},
                                                            "name": {"type": "string"}
                                                        },
                                                        "required": ["id", "name"],
                                                        "additionalProperties": False
                                                    }
                                                }
                                            },
                                            "additionalProperties": False
                                        }
                                    ]
                                },

                                "vulnerability_type": {
                                    "type": "object",
                                    "properties": {
                                        "type": {"type": "string"},
                                        "exploitation_techniques": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "id":   {"type": "string"},
                                                    "name": {"type": "string"}
                                                },
                                                "required": ["id", "name"],
                                                "additionalProperties": False
                                            }
                                        },
                                        "primary_impact": {
                                            "type": "array",
                                            "items": {"type": "string"}
                                        },
                                        "secondary_impact": {
                                            "type": "array",
                                            "items": {"type": "string"}
                                        }
                                    },
                                    "required": ["type"],
                                    "additionalProperties": False
                                }
                            },
                            "required": ["explaination", "vulnerability_type"],
                            "additionalProperties": False
                        },

                        # -------- ATT&CK 相关列表 --------
                        "related_attcks": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id":   {"type": "string"},
                                    "name": {"type": "string"}
                                },
                                "required": ["id", "name"],
                                "additionalProperties": False
                            }
                        },
                        "gt_attcks": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id":   {"type": "string"},
                                    "name": {"type": "string"}
                                },
                                "required": ["id", "name"],
                                "additionalProperties": False
                            }
                        },
                        "attck_patterns": {
                            "type": "array",
                            "items": {"type": "object"}
                        },
                        "related_attck_patterns": {
                            "type": "array",
                            "items": {"type": "object"}
                        },

                        # -------- 统计字段 --------
                        "count_attck_patterns": {
                            "type": "integer",
                            "minimum": 0
                        },
                        "count_related_attck_patterns": {
                            "type": "integer",
                            "minimum": 0
                        }
                    },

                    # 必填字段
                    "required": [
                        "cve_id",
                        "description",
                        "cve_mapping"
                    ],
                    "additionalProperties": False
                }
            }
        },
        "required": ["cve_data_items"],
        "additionalProperties": False
    }

     # ----------------------------- 执行写入 -----------------------------
    async def execute(self, params: Dict) -> List[TextContent]:
        """
        MCP 调用入口（同步阻塞版）
        直接 add_documents → wait_for_task → 返回结果
        """
        try:
            # 1. 参数检查
            if "cve_data_items" not in params:
                return [TextContent(type="text", text="缺少参数: cve_data_items")]

            cve_data_items = params["cve_data_items"]
            if not isinstance(cve_data_items, list) or not cve_data_items:
                return [TextContent(type="text", text="cve_data_items 必须是非空数组")]

            # 2. 写入 / 更新（Meilisearch 的 add_documents 对 primary_key 做 upsert）
            task = self.index.add_documents(cve_data_items)

            # 3. 等待任务完成（阻塞）
            task_info = self.index.wait_for_task(task.task_uid)

            if task_info.status != "succeeded":
                # 失败时将错误信息返回
                err_msg = f"Meilisearch 任务失败: {task_info.error}"
                logger.error(err_msg)
                return [TextContent(type="text", text=err_msg)]

            # 4. 成功
            added_cnt = task_info.details.get("receivedDocuments", "未知")
            ok_msg = (
                f"✅ 写入 / 更新成功！\n"
                f"任务 UID: {task.task_uid}\n"
                f"处理文档数量: {added_cnt}"
            )
            return [TextContent(type="text", text=ok_msg)]

        except MeilisearchApiError as api_err:
            msg = f"Meilisearch API 错误: {api_err.message}"
            logger.error(msg)
            return [TextContent(type="text", text=msg)]

        except Exception as exc:
            logger.exception("CVEAddTool 执行异常: %s", exc)
            return [TextContent(type="text", text=f"执行异常: {exc}")]

class CVEDeleteTool:
    """
    CVE 漏洞数据库删除工具（基于 Meilisearch）
    支持一次删除一个或多个 cve_id。
    """

    def __init__(self):
        self.name = "cve_delete"
        self.description = self._get_tool_description()
        self.input_schema = self._get_input_schema()

        self.client = Client(
            MEILISEARCH_CONFIG["host"],
            MEILISEARCH_CONFIG["api_key"]
        )
        self.index = self.client.index(MEILISEARCH_CONFIG["index_name"])

    # ---------------------- 工具描述 ----------------------
    def _get_tool_description(self) -> str:
        return '''
            CVE 漏洞数据库删除工具（Meilisearch）

            参数示例：
            {
                "cve_ids": ["CVE-2023-12345", "CVE-2022-0916"]
            }

            - cve_ids : 必填，字符串或字符串数组，表示要删除的 CVE ID。
            '''

    # ---------------------- 输入 JSON-Schema ----------------------
    def _get_input_schema(self) -> Dict:
        return {
            "type": "object",
            "properties": {
                "cve_ids": {
                    "oneOf": [
                        {  # 单个字符串
                            "type": "string",
                            "pattern": "^CVE-[0-9]{4}-[0-9]+$"
                        },
                        {  # 字符串数组
                            "type": "array",
                            "items": {
                                "type": "string",
                                "pattern": "^CVE-[0-9]{4}-[0-9]+$"
                            },
                            "minItems": 1
                        }
                    ]
                }
            },
            "required": ["cve_ids"],
            "additionalProperties": False
        }

    # ------------------------- 执行 -------------------------
    async def execute(self, params: Dict) -> List[TextContent]:
        """
        MCP 调用入口：删除指定文档
        """
        try:
            cve_ids_param = params["cve_ids"]

            # 统一成 list[str]
            if isinstance(cve_ids_param, str):
                cve_ids: List[str] = [cve_ids_param]
            else:
                cve_ids = cve_ids_param

            if not cve_ids:
                return [
                    TextContent(type="text", text="cve_ids 不能为空")
                ]

            # 删除
            task = self.index.delete_documents(cve_ids)
            task_info = self.index.wait_for_task(task.task_uid)

            if task_info.status != "succeeded":
                err = task_info.error or {}
                msg = f"❌ 删除任务失败 (UID={task.task_uid}): {err.get('message')}"
                logger.error(msg)
                return [TextContent(type="text", text=msg)]

            msg = (
                f"🗑️ 已成功删除 {len(cve_ids)} 条记录\n"
                f"(任务 UID: {task.task_uid})"
            )
            return [TextContent(type="text", text=msg)]

        except MeilisearchApiError as api_err:
            err_msg = f"Meilisearch API 错误: {api_err.message}"
            logger.error(err_msg)
            return [TextContent(type="text", text=err_msg)]

        except Exception as exc:
            logger.exception("CVEDeleteTool 执行异常: %s", exc)
            return [TextContent(type="text", text=f"执行异常: {exc}")]

# 注册到 MCP
tool_registry.register(CVESearchTool())
tool_registry.register(CVEAddTool())
tool_registry.register(CVEDeleteTool())