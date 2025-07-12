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
                        "year":       {"type": "integer", "minimum": 1999, "maximum": 2025},
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


# 注册到 MCP
tool_registry.register(CVESearchTool())
